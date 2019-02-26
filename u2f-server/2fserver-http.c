#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "2fserver-http.h"
#include "2fserver-support.h"
#include "2fserver-model.h"
#include "u2fdbt.h"

static const char method_GET[] = "GET";
static const char method_POST[] = "POST";

static const char cookie_Txn[] = "Txn";

static const char header_Content_Type[] = "Content-Type";
static const char header_Location[] = "Location";
static const char ct_text_plain[] = "text/plain";
static const char ct_application_json[] = "application/json";

static const int rcode_ok = 200;
static const int rcode_accepted = 202;
static const char str_accepted[] = "accepted\n";
static struct MHD_Response *resp_accepted;
static const int rcode_no_challenge = 204;
static struct MHD_Response *resp_no_challenge;
static const int rcode_forbidden = 403;
static const char str_forbidden[] = "forbidden\n";
static struct MHD_Response *resp_forbidden;
static const int rcode_not_found = 404;
static const char str_not_found[] = "not found\n";
static struct MHD_Response *resp_not_found;
static const int rcode_bad_method = 405;
static const char str_bad_method[] = "bad method\n";
static struct MHD_Response *resp_bad_method;
static const int rcode_internal_error = 500;
static const char str_internal_error[] = "internal error\n";
static struct MHD_Response *resp_internal_error;

/* These must not contain %. */
static const char prefix_auth[] = "/auth/";
static const char prefix_register[] = "/register/";

static const char *
after_prefix(const char *string, const char *prefix, size_t prefix_len)
{
    if (prefix_len == 0)
        prefix_len = strlen(prefix);
    if (strncmp(string, prefix, prefix_len))
        return NULL;
    return string + prefix_len;
}

#define after_prefix_static(string, prefix) \
    after_prefix(string, prefix, sizeof(prefix)-1)

static struct MHD_Response *
create_plain_persistent_response(const char *text, size_t len)
{
    struct MHD_Response *result =
        MHD_create_response_from_buffer(len, (void *)text, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(result, header_Content_Type, ct_text_plain);
    return result;
}

#define create_static_response(string) \
    create_plain_persistent_response(string, sizeof(string)-1)

enum RequestState {
    REQUEST_SUSPENDED_CHALLENGE = 1
};

struct PendingRequest {
    twofserver_TxnId txn_id;
    enum RequestState state;
};

static void
handle_mhd_panic(void *unused, const char *file, unsigned line,
                 const char *reason)
{
    (void)unused;
    /* TODO: maybe re-exec? */
    twofserver_eprintf("MHD panic: %s:%u: %s", file, line, reason);
    _exit(70);
}

char *format_path(const char *format, const char *prefix, twofserver_TxnId *txn_id)
{
  int prefix_len = strlen(prefix);
  int txn_len = TWOFSERVER_TXN_ID_LEN * 2;

  unsigned char *hex=malloc(txn_len+1);
  bin_to_strhex(txn_id->bytes, TWOFSERVER_TXN_ID_LEN, &hex);

  char *result=malloc(prefix_len + txn_len + 1);
  sprintf(result, format, prefix, hex);
  return result;
}

static int
get_auth_challenge(struct MHD_Connection *conn,
                   twofserver_TxnId txn_id, void **state_cell)
{
    /* Authentication challenge is being requested. */
    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(txn_id);

    if (record)
    {
        /* Operation already pending. */
        enum twofserver_ChallengeResultType chaltype;
        const char *chaltext =
            twofserver_challenge_for_auth(record, &chaltype);
        twofserver_unlock_pending_auth(record);
        record = NULL;

        int rcode = 0;
        struct MHD_Response *resp = NULL;
        bool free_resp = false;
        const char *redirect;

        /* TODO: switch indentation is weird for no good reason */
        switch (chaltype)
        {
            case TWOFSERVER_CHALLENGE_PROVIDED:
                rcode = rcode_ok;
                resp = MHD_create_response_from_buffer(
                    strlen(chaltext), (void *)chaltext, MHD_RESPMEM_MUST_COPY);
                free_resp = true;
                break;
    
            case TWOFSERVER_CHALLENGE_UNNECESSARY:
                rcode = rcode_no_challenge;
                resp = resp_no_challenge;
                break;
    
            case TWOFSERVER_CHALLENGE_REGISTRATION_REQUIRED:
                redirect = format_path("%s%I", prefix_register, &txn_id);
                rcode = 303;
                resp = MHD_create_response_from_buffer(
                    0, "", MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(resp, header_Content_Type, ct_text_plain);
                MHD_add_response_header(resp, header_Location, redirect);
                free((void *)redirect);
                redirect = NULL;
                free_resp = true;
                break;
                /* fall through until implemented */
    
            default:
                /* Whoa, that's wrong. */
                rcode = rcode_internal_error;
                resp = resp_internal_error;
                break;
        }

        int ok = MHD_queue_response(conn, rcode, resp);
        if (free_resp)
        {
            MHD_destroy_response(resp);
            resp = NULL;
        }
        return ok;
    }
    else /* !record */
    {
        /* This request arrived first, so we have to wait to
           respond to it until the OpenVPN auth succeeds. */
        struct PendingRequest *suspended =
            calloc(1, sizeof(struct PendingRequest));
        /* TODO: log OOM */
        if (!suspended)
            return MHD_NO;
        suspended->state = REQUEST_SUSPENDED_CHALLENGE;
        twofserver_txn_id_copy(&suspended->txn_id, &txn_id);
        *state_cell = suspended;

        struct twofserver_PendingAuth *record =
            twofserver_new_pending_auth(txn_id);
        record->challenge_conn = conn;
        twofserver_queue_pending_auth(record);

        /* No response yet. */
        MHD_suspend_connection(conn);
        /* TODO: check return of MHD_suspend_connection */
        return MHD_YES;
    }
}

static int
post_auth_attempt(struct MHD_Connection *conn,
                  twofserver_TxnId txn_id,
                  const char *data, size_t *data_size,
                  void **state_cell)
{
    /* Response to authentication challenge is being posted. */
    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(txn_id);
    if (!record)
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);

    if (twofserver_check_auth_response(record, data, *data_size))
    {
        twofserver_pass_pending_auth(record);
        return MHD_queue_response(conn, rcode_accepted, resp_accepted);
    }
    else
    {
        twofserver_fail_pending_auth(record);
        return MHD_queue_response(conn, rcode_forbidden, resp_forbidden);
    }
}

static int
get_reg_challenge(struct MHD_Connection *conn, twofserver_TxnId txn_id,
                  void **state_cell)
{
    /* Registration challenge is being requested. */
    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(txn_id);
    if (!record)
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);

    /* We should only ever get here after a redirect from an
       authentication, so the record should already have
       existed. Otherwise, we wouldn't have been able to respond to
       the first request. */

    if (twofserver_already_registered(record))
    {
        /* TODO: do we need to handle multiple key registrations? */
        twofserver_unlock_pending_auth(record);
        return MHD_queue_response(conn, rcode_no_challenge, resp_no_challenge);
    }

    if (!twofserver_can_register(record))
    {
        twofserver_unlock_pending_auth(record);
        return MHD_queue_response(conn, rcode_forbidden, resp_forbidden);
    }

    const char *chaltext = twofserver_challenge_for_reg(record);
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(chaltext), (void *)chaltext, MHD_RESPMEM_MUST_COPY);
    int ok = MHD_queue_response(conn, rcode_ok, resp);
    MHD_destroy_response(resp);
    return ok;
}

static int
post_reg_attempt(struct MHD_Connection *conn,
                 twofserver_TxnId txn_id,
                 const char *data, size_t *data_size,
                 void **state_cell)
{
    /* Response to registration challenge is being posted. */
    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(txn_id);
    if (!record)
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);

    if (!twofserver_check_reg_response(record, data, *data_size))
    {
        twofserver_fail_pending_auth(record);
        return MHD_queue_response(conn, rcode_forbidden, resp_forbidden);
    }

    twofserver_process_reg(record);
    twofserver_pass_pending_auth(record);
    return MHD_queue_response(conn, rcode_accepted, resp_accepted);
}

static int
handle_request(void *unused, struct MHD_Connection *conn,
               const char *url, const char *method, const char *version,
               const char *data, size_t *data_size, void **state_cell)
{
    /* TODO: do we need first-factor auth on each request here? */
    const char *tail;

    if ((tail = after_prefix_static(url, prefix_auth)))
    {
        twofserver_TxnId id;
        int err = twofserver_txn_id_parse(&id, tail);
        if (err)
        {
            return MHD_queue_response(conn, rcode_not_found, resp_not_found);
        }

        if (!strcmp(method, method_GET))
        {
            return get_auth_challenge(conn, id, state_cell);
        }
        else if (!strcmp(method, method_POST))
        {
            return post_auth_attempt(conn, id, data, data_size, state_cell);
        }
        else
        {
            return MHD_queue_response(conn, rcode_bad_method, resp_bad_method);
        }
    }
    else if ((tail = after_prefix_static(url, prefix_register)))
    {
        twofserver_TxnId id;
        int err = twofserver_txn_id_parse(&id, tail);
        if (err)
        {
            return MHD_queue_response(conn, rcode_not_found, resp_not_found);
        }

        if (!strcmp(method, method_GET))
        {
            return get_reg_challenge(conn, id, state_cell);
        }
        else if (!strcmp(method, method_POST))
        {
            return post_reg_attempt(conn, id, data, data_size, state_cell);
        }
        else
        {
            return MHD_queue_response(conn, rcode_bad_method, resp_bad_method);
        }
    }
    else
    {
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);
    }
}

void
twofserver_start_http(unsigned port)
{
    MHD_set_panic_func(&handle_mhd_panic, NULL);

    /* TODO: MHD_USE_SSL */
    unsigned flags = 0
        | MHD_USE_DUAL_STACK
        | MHD_USE_SELECT_INTERNALLY
        | MHD_USE_PEDANTIC_CHECKS
        | MHD_USE_POLL
        | MHD_USE_SUSPEND_RESUME;

    /* TODO:
         - less-hardcoded limits?
         - Move processing into main thread?
         - Do we need to use our own listening socket?
         - Need to add TLS certificate here.
         - TLS version/ciphers priority list.
    */
    struct MHD_OptionItem options[] = {
        { MHD_OPTION_CONNECTION_LIMIT, 500, NULL },
        { MHD_OPTION_CONNECTION_TIMEOUT, 5, NULL },
        { MHD_OPTION_PER_IP_CONNECTION_LIMIT, 2, NULL },
        { MHD_OPTION_END, 0, NULL }
    };

    struct MHD_Daemon *mhd =
        MHD_start_daemon(flags, port,
                         NULL, NULL, /* no access policy callback */
                         &handle_request, NULL,
                         MHD_OPTION_ARRAY, options,
                         MHD_OPTION_END);
    /* TODO: check result */

    /* TODO: check return codes */

    resp_accepted = create_static_response(str_accepted);
    /* Must have zero-length content because HTTP code 204 implies that. */
    resp_no_challenge = MHD_create_response_from_buffer(
        0, (void *)"", MHD_RESPMEM_PERSISTENT);
    resp_forbidden = create_static_response(str_forbidden);
    resp_not_found = create_static_response(str_not_found);
    resp_bad_method = create_static_response(str_bad_method);
    resp_internal_error = create_static_response(str_internal_error);
}
