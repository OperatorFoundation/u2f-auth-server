#ifndef COMM_2FSERVER_H
#define COMM_2FSERVER_H

#include <inttypes.h>

#define BACKEND_PROTOCOL_VERSION 2
#define MAX_PACKET_BYTES 1024
#define MAX_PACKET_FDS 1

enum control_socket_opcode
{
    OP_TERMINATE, /* -> */
    OP_TERMINATE_ACK, /* <- */
    OP__INVALID_1,
    OP_INITIALIZED, /* <- (uint8_t proto_version) */
    OP_AUTH_REQUEST, /* -> (string txn_id, string username, string password) + (fd) */
    OP_AUTH_RESPONSE, /* <- (uint8_t response) */
    OP_ERROR, /* <-> (string message) */
    OP__INVALID_2,
    OP_LAST
};

enum
{
    AUTH_RESPONSE_IMMEDIATE_PERMIT,
    AUTH_RESPONSE_PENDING,
    AUTH_RESPONSE_IMMEDIATE_DENY,
    AUTH_RESPONSE_ERROR
};

ssize_t comm_2fserver_send_packet(int sock, uint8_t opcode, const char *fmt, ...);
int comm_2fserver_parse_packet(const char *packet, size_t len,
                               struct msghdr *msg, const char *fmt, ...);

static inline ssize_t
comm_2fserver_send_error(int sock, const char *error)
{
    return comm_2fserver_send_packet(sock, OP_ERROR, "s", error);
}

#endif /* !COMM_2FSERVER_H */
