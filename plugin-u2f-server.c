#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include "openvpn-plugin.h"
#include "comm-2fserver.h"

#define U2F_SERVER_PLUGIN_NAME "u2f-server"

struct u2f_server_context
{
    struct openvpn_plugin_callbacks *global_vtab;
    pid_t child;
    int control_socket;
};

static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

static void
u2f_server_log(struct u2f_server_context *ctx,
               openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, U2F_SERVER_PLUGIN_NAME, fmt, va);
    va_end(va);
}

static void
exec_child(int control_socket)
{
    /* Control socket needs to make it to the child process.
       TODO: maybe use posix_spawn here?
     */
    fcntl(control_socket, F_SETFD, fcntl(control_socket, F_GETFD) & ~FD_CLOEXEC);

    char arg0[32];
    snprintf(arg0, sizeof(arg0), "-s%d", control_socket);
    /* TODO: better way of finding executable */
    execlp("openvpn-2fserver", "openvpn-2fserver", arg0, NULL);
    /* exec failed. */
    abort();
}

static int
wait_child_init(int control_socket)
{
    char packet[1024];
    /* XXX */
    return recv(control_socket, packet, 1024, 0) <= 0;
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(int version,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct u2f_server_context *ctx =
        calloc(1, sizeof(struct u2f_server_context));
    if (!ctx)
        return OPENVPN_PLUGIN_FUNC_ERROR;
    ctx->global_vtab = args->callbacks;

    pid_t child = -1;
    int control_socket[2] = { -1, -1 };
    int err;

    /* Linux-specific: SOCK_CLOEXEC */
    err = socketpair(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0, control_socket);
    if (err)
        goto bad;
    child = fork();
    if (child == -1)
        goto bad;
    if (child == 0)
    {
        /* In child process. */
        close(control_socket[0]);
        control_socket[0] = -1;
        exec_child(control_socket[1]);
        /* Never returns. */
    }
    else
    {
        /* In main process. */
        u2f_server_log(ctx, PLOG_NOTE, "started 2fserver with PID %d", child);
        close(control_socket[1]);
        control_socket[1] = -1;
        err = wait_child_init(control_socket[0]);
        if (err)
            goto bad;
    }

    ctx->child = child;
    ctx->control_socket = control_socket[0];

    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    ret->handle = (openvpn_plugin_handle_t *)ctx;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

bad:
    if (control_socket[0] != -1)
    {
        close(control_socket[0]);
    }

    if (control_socket[1] != -1)
    {
        close(control_socket[1]);
    }

    if (child != 0 && child != -1)
    {
        kill(child, SIGKILL);
        /* TODO: waitpid loop */
        waitpid(child, NULL, 0);
    }

    free(ctx);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, int type,
                       const char *argv[], const char *envp[])
{
    struct u2f_server_context *ctx =
        (struct u2f_server_context *)handle;
    if (type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    const char *username = get_env("username", envp);
    const char *password_input = get_env("password", envp);
    const char *common_name = get_env("common_name", envp);
    const char *origin = get_env("origin", envp);
    const char *acf = get_env("auth_control_file", envp);
    int acf_fd = -1;
    char *password_dup = NULL;
    char *password_proper = NULL;
    char *txn_id_string = NULL;

    /* Note that in optional mode these could be empty strings, not just NULL. */
    if (!username || !password_input)
    {
        u2f_server_log(ctx, PLOG_ERR,
                       "expected username/password in environment set");
        goto bad;
    }

    if (!acf)
    {
        u2f_server_log(ctx, PLOG_ERR,
                       "can't do deferred auth with no auth_control_file!");
        goto bad;
    }

    acf_fd = open(acf, O_WRONLY, 0600);
    if (acf_fd == -1)
    {
        u2f_server_log(ctx, PLOG_ERR | PLOG_ERRNO,
                       "open auth_control_file %s", acf);
        goto bad;
    }

    password_dup = strdup(password_input);
    if (!password_dup)
    {
        u2f_server_log(ctx, PLOG_ERR | PLOG_ERRNO, "strdup");
        goto bad;
    }

    /* password_dup, copy of password_input, really contains
       TXNID:PASSWORD. */
    txn_id_string = password_dup;
    char *password_separator = strchr(password_dup, ':');
    if (!password_separator)
    {
        u2f_server_log(ctx, PLOG_ERR,
                       "password input has no txn id separator");
        goto bad;
    }

    /* Mutate the duplicated string to split at the colon. */
    *password_separator = '\0';
    password_proper = password_separator+1;

    comm_2fserver_send_packet(ctx->control_socket, OP_AUTH_REQUEST,
                              "Fssss", acf_fd, txn_id_string,
                              username, password_proper, origin);
    close(acf_fd);
    acf_fd = -1;

    /* TODO: factor out receive-and-parse */
    char response[MAX_PACKET_BYTES];
    ssize_t len;
    do {
        len = recv(ctx->control_socket, response, MAX_PACKET_BYTES, 0);
    } while (len < 0 && errno == EAGAIN);

    if (len == 0)
    {
        u2f_server_log(ctx, PLOG_ERR, "2fserver sent bad zero-length response");
        goto bad;
    }
    else if (len == -1)
    {
        u2f_server_log(ctx, PLOG_ERR | PLOG_ERRNO, "receiving from 2fserver");
        goto bad;
    }

    const char *error;
    switch ((unsigned char)response[0])
    {
        case OP_AUTH_RESPONSE:
            /* Keep going. */
            break;
        case OP_ERROR:
            if (comm_2fserver_parse_packet(response, len, NULL, "s", &error))
                u2f_server_log(ctx, PLOG_ERR, "2fserver sent bad error packet");
            else
                u2f_server_log(ctx, PLOG_ERR, "2fserver sent error: %s", error);
            goto bad;
        default:
            u2f_server_log(ctx, PLOG_ERR, "2fserver sent wrong response opcode: %d",
                           (unsigned char)response[0]);
            goto bad;
    }

    unsigned char result;
    if (comm_2fserver_parse_packet(response, len, NULL, "b", &result))
    {
        u2f_server_log(ctx, PLOG_ERR, "2fserver sent malformed auth response");
        goto bad;
    }

    /* Clean up before returning result. */
    free(password_dup);

    switch (result)
    {
        case AUTH_RESPONSE_IMMEDIATE_PERMIT:
            u2f_server_log(ctx, PLOG_DEBUG, "2fserver responds: immediate permit");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        case AUTH_RESPONSE_IMMEDIATE_DENY:
            u2f_server_log(ctx, PLOG_DEBUG, "2fserver responds: immediate deny");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        case AUTH_RESPONSE_PENDING:
            u2f_server_log(ctx, PLOG_DEBUG, "2fserver responds: pending");
            return OPENVPN_PLUGIN_FUNC_DEFERRED;
        case AUTH_RESPONSE_ERROR:
            u2f_server_log(ctx, PLOG_ERR, "2fserver responds: processing error");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        default:
            u2f_server_log(ctx, PLOG_ERR, "2fserver sent unrecognized auth response result code: %d",
                           result);
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }

bad:
    /* Clean up for error. */
    if (acf_fd != -1)
        close(acf_fd);
    if (password_dup)
        free(password_dup);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct u2f_server_context *ctx = (struct u2f_server_context *)handle;

    if (ctx->control_socket != -1)
    {
        u2f_server_log(ctx, PLOG_NOTE, "stopping 2fserver with PID %d, sending SIGTERM",
                       ctx->child);
        close(ctx->control_socket);
        kill(ctx->child, SIGTERM);
        /* TODO: waitpid loop */
        waitpid(ctx->child, NULL, 0);
    }

    free(ctx);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle)
{
    /* TODO: should this just be the same as above? */
    struct u2f_server_context *ctx = (struct u2f_server_context *)handle;

    if (ctx->control_socket != -1)
    {
        u2f_server_log(ctx, PLOG_NOTE, "stopping 2fserver with PID %d, sending SIGTERM",
                       ctx->child);
        close(ctx->control_socket);
        kill(ctx->child, SIGTERM);
        /* TODO: waitpid loop */
        waitpid(ctx->child, NULL, 0);
    }

    free(ctx);
}
