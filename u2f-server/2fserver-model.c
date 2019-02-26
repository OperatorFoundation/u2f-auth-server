#define _XOPEN_SOURCE 500       /* FIXME: temporary for random() */
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <u2f-server/u2f-server.h>
#include "2fserver-model.h"
#include "u2fdbt.h"

static struct twofserver_PendingAuth *the_table;
static size_t the_table_cap;
static pthread_mutex_t the_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct twofserver_PendingAuth *the_record;

int64_t getCurrentTimestamp() {
    struct timespec tms;

    if(clock_gettime(CLOCK_REALTIME, &tms)) {
        return -1;
    }

    /* seconds, multiplied with 1 million */
    int64_t micros = tms.tv_sec * 1000000;

    /* Add full microseconds */
    micros += tms.tv_nsec/1000;

    /* round up if necessary */
    if (tms.tv_nsec % 1000 >= 500) {
        ++micros;
    }

    return micros;
}

/* Capacity must be a power of two. See below where this is used. */
int
twofserver_allocate_table(size_t capacity)
{
    assert(!the_table);
    assert((capacity & (capacity-1)) == 0);
    struct twofserver_PendingAuth *array =
        calloc(sizeof(struct twofserver_PendingAuth), capacity);
    if (!array)
        return -1;
    
    the_table = array;
    the_table_cap = capacity;

    return 0;
}

static inline unsigned
index_for_txn_id(twofserver_TxnId id)
{
    return ((unsigned)(unsigned char)id.bytes[0]
            | ((unsigned)(unsigned char)id.bytes[1] << 8)
            | ((unsigned)(unsigned char)id.bytes[2] << 16)
            | ((unsigned)(unsigned char)id.bytes[3] << 24));
}

static inline unsigned
step_for_txn_id(twofserver_TxnId id, size_t capacity)
{
    /* Capacity must be a power of two, enforced above. */
    return
        ((size_t)1u
         | (size_t)(unsigned char)id.bytes[4]
         | ((size_t)(unsigned char)id.bytes[5] << 8)
         | ((size_t)(unsigned char)id.bytes[6] << 16)
         | ((size_t)(unsigned char)id.bytes[7] << 24))
        & (capacity-1);
}

#if 0
/* The mutex must be taken. */
static unsigned
lookup_txn_id(twofserver_TxnId id)
{
    unsigned here = index_for_txn_id(id);
    unsigned step = step_for_txn_id(id, the_table_cap);
    /* TODO: fewer max_steps? Constrain max load? */
    for (size_t max_steps = the_table_cap; max_steps > 0; max_steps--) {
        if (!twofserver_pending_auth_exists(&the_table[here]) /* TODO */
            || twofserver_txn_id_equal(the_table[here].txn_id, id)) {
            return here;
        }
    }

    return (unsigned)-1;
}
#endif 

struct twofserver_PendingAuth *
twofserver_new_pending_auth(twofserver_TxnId id)
{
    int err;
    struct twofserver_PendingAuth *record =
        calloc(sizeof(struct twofserver_PendingAuth), 1);
    if (!record)
        return NULL;
    twofserver_txn_id_copy(&record->txn_id, &id);

    /* Everything else is either initialized to zero or is unset
       based on something else initialized to zero. */
    return record;
}

void
twofserver_queue_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(!record->locked);
    pthread_mutex_lock(&the_table_mutex);
    /* FIXME: leaks the previous record */
    the_record = record;
    pthread_mutex_unlock(&the_table_mutex);
}

void
twofserver_discard_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(!record->locked);
    free(record);
}

struct twofserver_PendingAuth *
twofserver_lock_pending_auth(twofserver_TxnId id)
{
    pthread_mutex_lock(&the_table_mutex);
    struct twofserver_PendingAuth *record = the_record;
    if (!record)
        goto eexist;
    if (twofserver_txn_id_cmp(&record->txn_id, &id))
        goto eexist;
    if (record->locked)
    {
        errno = EBUSY;
        goto bad;
    }
    record->locked = true;
    pthread_mutex_unlock(&the_table_mutex);
    return record;

  eexist:
    errno = EEXIST;
    /* fall through */
  bad:
    pthread_mutex_unlock(&the_table_mutex);
    return NULL;
}

void
twofserver_unlock_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(record->locked);
    pthread_mutex_lock(&the_table_mutex);
    record->locked = false;
    pthread_mutex_unlock(&the_table_mutex);
}

static void
destroy(struct twofserver_PendingAuth *record)
{
    assert(record->locked);
    pthread_mutex_lock(&the_table_mutex);
    assert(the_record == record);
    the_record = NULL;
    free(record);
    pthread_mutex_unlock(&the_table_mutex);
}

static void
write_acf(struct twofserver_PendingAuth *record, char ch)
{
    if (record->success1 && record->final_response_fd != -1)
    {
        record->final_response_char = ch;
        /* TODO: full_write? */
        write(record->final_response_fd, &ch, 1);
        close(record->final_response_fd);
        record->final_response_fd = -1;
    }
}

void
twofserver_pass_pending_auth(struct twofserver_PendingAuth *record)
{
    write_acf(record, '1');
    destroy(record);
}

void
twofserver_fail_pending_auth(struct twofserver_PendingAuth *record)
{
    write_acf(record, '0');
    destroy(record);
}

/* Returns -1 for chars that are not hex digits. */
static int
hex_ctoi(char ch)
{
    if ('0' <= ch && ch <= '9')
        return (int)ch - '0';
    else if ('a' <= ch && ch <= 'f')
        return 10 + ((int)ch - 'a');
    else if ('A' <= ch && ch <= 'F')
        return 10 + ((int)ch - 'A');
    else
        return -1;
}

int
twofserver_txn_id_parse(twofserver_TxnId *out, const char *in)
{
    char *dst = &out->bytes[0];
    if (strlen(in) != TWOFSERVER_TXN_ID_LEN * 2)
        return -1;

    for (int i = 0; i < TWOFSERVER_TXN_ID_LEN; i++)
    {
        /* byte < 0 iff either hex_ctoi returned a value < 0 */
        int byte = (hex_ctoi(in[i*2+0]) << 4) | hex_ctoi(in[i*2+1]);
        if (byte < 0)
            return -1;
        out->bytes[i] = byte;
    }

    return 0;
}

const char *
twofserver_challenge_for_auth(struct twofserver_PendingAuth *record,
                              enum twofserver_ChallengeResultType *chaltype)
{
    u2fs_ctx_t *ctx;
    char *output;

    const char *origin=record->origin;
    const char *appid="OpenVPN u2f-auth";

    u2fs_init(&ctx);
    u2fs_set_origin(ctx, origin);
    u2fs_set_appid(ctx, appid);
    u2fs_authentication_challenge(ctx, &output);

    *chaltype = TWOFSERVER_CHALLENGE_PROVIDED;

    u2fs_done(ctx);

    return output;
}

bool
twofserver_check_auth_response(struct twofserver_PendingAuth *record,
                                const char *response, size_t response_len)
{
    u2fs_ctx_t *ctx;
    u2fs_auth_res_t *output;

    const char *origin=record->origin;
    const char *appid="OpenVPN u2f-auth";

    while (response_len > 0 && strchr("\r\n", response[response_len-1]))
        response_len--;
    if (response_len != 4)
        return false;
    /* I can't find right now whether the response data is zero-terminated,
       so let's assume we have to copy... */
    char response_copy[5];
    assert(response_len+1 <= sizeof(response_copy));
    memcpy(response_copy, response, response_len);
    response_copy[response_len] = '\0';

    char *end;
    unsigned long number = strtoul(response_copy, &end, 16);
    if (*end != '\0')
        return false;
    if (!(number <= 0xffff))
        return false;

    u2fs_init(&ctx);
    u2fs_set_origin(ctx, origin);
    u2fs_set_appid(ctx, appid);

    u2fs_rc result = u2fs_authentication_verify(ctx, response, &output);
    u2fs_done(ctx);

    switch(result)
    {
      case U2FS_OK:
        return 1;
      default:
        return 0;
    }
}

const char *
twofserver_challenge_for_reg(struct twofserver_PendingAuth *record)
{
    u2fs_ctx_t *ctx;
    char *output;

    const char *origin=record->origin;
    const char *appid="OpenVPN u2f-auth";

    u2fs_init(&ctx);
    u2fs_set_origin(ctx, origin);
    u2fs_set_appid(ctx, appid);

    u2fs_rc result = u2fs_registration_challenge(ctx, &output);
    u2fs_done(ctx);

    return output;
}

bool
twofserver_already_registered(struct twofserver_PendingAuth *pending)
{
    struct u2fdbt_File *db=u2fdbt_open("users.dbt");
    struct u2fdbt_Record *record=u2fdbt_find(db, pending->user);

    // Cannot modify user record, as user does not exists.
    if(record==NULL) {
        u2fdbt_close(db);
        return 0;
    }

    return record->flags & U2FDBT_FLAG_HAVE_KEYS;
}

bool
twofserver_can_register(struct twofserver_PendingAuth *pending)
{
    struct u2fdbt_File *db=u2fdbt_open("users.dbt");
    struct u2fdbt_Record *record=u2fdbt_find(db, pending->user);

    // Cannot modify user record, as user does not exists.
    if(record==NULL) {
        u2fdbt_close(db);
        return 0;
    }

    int selfRegistration = record->flags & U2FDBT_FLAG_SELF_REGISTER;
    int registered = record->flags & U2FDBT_FLAG_HAVE_KEYS;

    return selfRegistration && (!registered);
}

bool
twofserver_check_reg_response(struct twofserver_PendingAuth *pending,
                              const char *response, size_t response_len)
{
    u2fs_ctx_t *ctx;
    u2fs_reg_res_t *output;

    const char *origin=pending->origin;
    const char *appid="OpenVPN u2f-auth";

    u2fs_init(&ctx);
    u2fs_set_origin(ctx, origin);
    u2fs_set_appid(ctx, appid);

    u2fs_rc result = u2fs_registration_verify(ctx, response, &output);
    u2fs_done(ctx);

    switch(result)
    {
      case U2FS_OK:
        pending->userkey=(char *)u2fs_get_registration_publicKey(output);
        pending->userkeysize=strlen(pending->userkey);
        pending->keyhandle=(char *)u2fs_get_registration_keyHandle(output);
        return 1;
      default:
        return 0;
    }
}

void
twofserver_process_reg(struct twofserver_PendingAuth *pending)
{
    struct u2fdbt_File *db=u2fdbt_open("users.dbt");
    struct u2fdbt_Record *record=u2fdbt_find(db, pending->user);

    // Cannot modify user record, as user does not exists.
    if(record==NULL) {
        u2fdbt_close(db);
        return;
    }

    record->flags = record->flags | U2FDBT_FLAG_HAVE_KEYS;
    record->record_mtime=getCurrentTimestamp();
    record->userkey=pending->userkey;
    record->userkeysize=pending->userkeysize;
    record->keyhandle=pending->keyhandle;

    u2fdbt_begin_update(db);
    u2fdbt_replace(db, record);
    u2fdbt_finish_update(db);
    u2fdbt_close(db);
}
