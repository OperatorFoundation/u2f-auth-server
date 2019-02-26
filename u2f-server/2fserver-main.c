#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <u2f-server/u2f-server.h>
#include "openvpn-plugin.h"
#include "../comm-2fserver.h"
#include "2fserver-http.h"
#include "2fserver-model.h"
#include "u2fdbt.h"

static const char program_name[] = "openvpn-2fserver";
static struct u2fdbt_File *user_db;

static void
open_user_database(void)
{
    /* TODO: unhardcode path */
    user_db = u2fdbt_open("users.db");
}

static bool
user_accepts_password(const char *username, const char *password)
{
    const struct u2fdbt_Record *record =
        u2fdbt_find(user_db, username);
    if (!record)
    {
        return false;
    }

    return u2fdbt_digest_accepts_password(record->pw_digest, password);
}

static int
do_auth_request(const char *packet, size_t len, struct msghdr *msg,
                const char **error)
{
    int fd = -1;
    int err;
    const char *username;
    const char *password;
    const char *origin;
    const char *txn_id_string;
    struct twofserver_PendingAuth *record;
    *error = "unknown error";

    if (comm_2fserver_parse_packet(packet, len, msg,
                                   "Fssss", &fd, &txn_id_string,
                                   &username, &password, &origin))
    {
        /* TODO: make sure parse contract ensures that vars are either
           unset or set to sane values even if parse fails partway through
        */
        *error = "malformed auth request";
        goto bad;
    }

    twofserver_TxnId id;
    err = twofserver_txn_id_parse(&id, txn_id_string);
    if (err)
    {
        *error = "cannot parse transaction ID";
        goto bad;
    }

    bool ok = user_accepts_password(username, password);
    if (!ok)
    {
        close(fd);
        return AUTH_RESPONSE_IMMEDIATE_DENY;
    }

    /* Leave the fd open for pending resolution. */
    record = twofserver_new_pending_auth(id);
    record->origin = (char *)origin;
    record->success1 = true;
    record->final_response_fd = fd;
    twofserver_queue_pending_auth(record);
    return AUTH_RESPONSE_PENDING;

bad:
    if (fd != -1)
        close(fd);
    return AUTH_RESPONSE_ERROR;
}

static void
control_loop(int sock)
{
    for (;;)
    {
        ssize_t len;
        union {
            char data[CMSG_SPACE(sizeof(int) * MAX_PACKET_FDS)];
            struct cmsghdr align;
        } ancillary;
        char packet[MAX_PACKET_BYTES];
        struct iovec iov = {
            .iov_base = packet,
            .iov_len = MAX_PACKET_BYTES
        };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = ancillary.data,
            .msg_controllen = sizeof(ancillary.data)
        };

        do {
            len = recvmsg(sock, &msg, 0);
        } while (len < 0 && errno == EAGAIN);

        if (len == 0)
        {
            comm_2fserver_send_error(sock, "bad zero-length packet");
            continue;
        }

        int result;
        const char *error;

        switch ((unsigned char)packet[0])
        {
            case OP_TERMINATE:
                comm_2fserver_send_packet(sock, OP_TERMINATE_ACK, "");
                /* return rather than break, to exit loop. */
                return;
            case OP_AUTH_REQUEST:
                error = NULL;
                result = do_auth_request(packet, (size_t)len, &msg, &error);
                if (result == AUTH_RESPONSE_ERROR && error)
                {
                    comm_2fserver_send_error(sock, error);
                }
                else
                {
                    comm_2fserver_send_packet(sock, OP_AUTH_RESPONSE, "b", result);
                }
                break;
            default:
                comm_2fserver_send_error(sock, "unrecognized opcode");
                break;
        }

        /* TODO (defensive): close_spare_fds(&msg); */
    }
}

/* This handler exists mainly for libmicrohttpd portability reasons as
   documented in section 1.6 of its manual. Note that technically this
   isn't required on Linux, but it'd be an easy omission when porting
   otherwise... */
static void
set_sigpipe_handler(void)
{
    struct sigaction sa = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_RESTART
    };
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGPIPE, &sa, NULL))
    {
        fprintf(stderr, "%s: cannot set SIGPIPE handler\n", program_name);
        exit(71);
    }
}

struct cli_args {
    int control_socket;
};

/* args are presumed valid on entry. */
static int
truemain(const struct cli_args *args)
{
    int control_socket = args->control_socket;
    set_sigpipe_handler();
    
    u2fs_rc result = u2fs_global_init(U2FS_DEBUG);
    switch(result)
    {
      case U2FS_OK:
        break;
      default:
        exit(67);
        return -1;
    }

    open_user_database();
    /* TODO: unhardcode port */
    twofserver_start_http(11080);

    comm_2fserver_send_packet(control_socket, OP_INITIALIZED,
                              "b", BACKEND_PROTOCOL_VERSION);
    control_loop(control_socket);
    return 0;
}

static int
parse_fd(const char *arg)
{
    errno = 0;
    unsigned long n = strtoul(arg, NULL, 10);
    if (errno)
        return -1;
#if ULONG_MAX > INT_MAX
    if (n > (unsigned long)INT_MAX)
        return -1;
#endif
    return (int)n;
}

static void
show_usage(void)
{
    fprintf(stderr, "Usage: %s -sSOCKET_FD\n", program_name);
    fputs("This program is normally only called by its attendant plugin.\n",
          stderr);
}

int
main(int argc, char *argv[])
{
    struct cli_args args = {
        .control_socket = -1
    };
    int option;

    while ((option = getopt(argc, argv, ":s:h")) != -1)
    {
        switch (option)
        {
            case 's':
                args.control_socket = parse_fd(optarg);
                break;
            case 'h':
                show_usage();
                exit(0);
            case ':':
                fprintf(stderr, "%s: option -%c requires an argument\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            case '?':
                fprintf(stderr, "%s: unrecognized option -%c\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            default:
                fprintf(stderr, "%s: error processing options\n",
                        program_name);
                show_usage();
                exit(64);
        }
    }

    if (args.control_socket == -1)
    {
        fprintf(stderr, "%s: no control socket found\n", program_name);
        show_usage();
        exit(66);
    }

    return truemain(&args);
}
