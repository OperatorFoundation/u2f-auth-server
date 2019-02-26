#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "comm-2fserver.h"

ssize_t
comm_2fserver_send_packet(int sock, uint8_t opcode, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);

    char packet[MAX_PACKET_BYTES] = { (unsigned char)opcode };
    char *fill = packet+1;
    size_t space = MAX_PACKET_BYTES-1;

    const char *string;
    size_t slen;
    int fds[MAX_PACKET_FDS];
    size_t nfds = 0;

    for (const char *f = fmt; *f; f++)
    {
        switch (*f)
        {
            case 'F':
                /* File descriptor. */
                if (nfds >= MAX_PACKET_FDS)
                    goto bad;
                fds[nfds++] = va_arg(va, int);
                break;

            case 'b':
                /* Single byte. */
                if (space < 1)
                    goto bad;
                *fill = (unsigned char)va_arg(va, int);
                fill++;
                space--;
                break;

            case 's':
                /* Null-terminated string. */
                string = va_arg(va, const char *);
                slen = strlen(string);
                if (space < (slen + 1))
                    goto bad;
                memcpy(fill, string, slen + 1);
                fill += (slen + 1);
                space -= (slen + 1);
                break;

            default:
                /* Unrecognized format character. */
                goto bad;
        }
    }

    va_end(va);

    union {
        char data[CMSG_SPACE(sizeof(int) * MAX_PACKET_FDS)];
        struct cmsghdr align;
    } ancillary;
    struct iovec iov = {
        .iov_base = packet,
        .iov_len = fill - packet
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    if (nfds > 0)
    {
        msg.msg_control = ancillary.data;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);
    }
    
    ssize_t len;
    do {
        len = sendmsg(sock, &msg, 0);
    } while (len == -1 && errno == EAGAIN);
    return len;

bad:
    /* TODO: maybe abort? */
    va_end(va);
    return -1;
}

int
comm_2fserver_parse_packet(const char *packet, size_t len,
                           struct msghdr *msg, const char *fmt, ...)
{
    if (len == 0)
        return -1;

    va_list va;
    va_start(va, fmt);

    const char *tail = packet+1;
    size_t remaining = len-1;
    char *fd_array = NULL;
    size_t fd_bytes = 0;
    if (msg)
    {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
             cmsg = CMSG_NXTHDR(msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS)
            {
                fd_array = (char *)CMSG_DATA(cmsg);
                fd_bytes = cmsg->cmsg_len - sizeof(struct cmsghdr);
                break;
            }
        }
    }

    const char *zero;

    for (const char *f = fmt; *f; f++)
    {
        switch (*f)
        {
            case 'F':
                /* File descriptor. */
                if (fd_bytes >= sizeof(int))
                {
                    memcpy(va_arg(va, int *), fd_array, sizeof(int));
                    fd_array += sizeof(int);
                    fd_bytes -= sizeof(int);
                }
                else
                {
                    goto bad;
                }
                break;

            case 'b':
                /* Single byte. */
                if (remaining < 1)
                    goto bad;
                *va_arg(va, unsigned char *) = (unsigned char)*tail;
                remaining--;
                tail++;
                break;

            case 's':
                /* Null-terminated string. */
                zero = memchr(tail, '\0', remaining);
                if (!zero)
                    goto bad;
                *va_arg(va, const char **) = tail;
                remaining -= (zero - tail) + 1;
                tail = zero + 1;
                break;

            default:
                /* Unrecognized format character. */
                goto bad;
        }
    }

    va_end(va);
    return 0;
bad:
    va_end(va);
    return -1;
}

