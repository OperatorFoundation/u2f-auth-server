#ifndef TWOFSERVER_STATE_H
#define TWOFSERVER_STATE_H 1

#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#define TWOFSERVER_TXN_ID_LEN 32

typedef struct {
    char bytes[TWOFSERVER_TXN_ID_LEN];
} twofserver_TxnId;

static inline void
twofserver_txn_id_copy(twofserver_TxnId *out, const twofserver_TxnId *in)
{
    memcpy(out, in, sizeof(twofserver_TxnId));
}

static inline int
twofserver_txn_id_cmp(const twofserver_TxnId *a, const twofserver_TxnId *b)
{
    /* TODO: where's the timing-safe memcmp again? */
    return memcmp(a, b, sizeof(twofserver_TxnId));
}

int twofserver_txn_id_parse(twofserver_TxnId *out, const char *in);

/* A PendingAuth structure may be owned by the store of pending
   authentications, locked for a particular consumer, or floating.
   Unlocked, owned PendingAuth pointers must not be held by consumers.

   From the perspective of a consumer of the store, the state
   transitions are:
     - new_pending_auth() -> floating
     - queue_pending_auth(floating) -> becomes owned
     - discard_pending_auth(floating) -> destroyed

     - lock_pending_auth(id) -> locked
     - unlock_pending_auth(locked) -> becomes owned
     - pass_pending_auth(locked) -> destroyed
     - fail_pending_auth(locked) -> destroyed

   TODO: that free/destroy distinction is kinda terrible
 */

struct twofserver_PendingAuth {
    twofserver_TxnId txn_id;
    bool locked;

    /* Value is set if success1 is set. File descriptor to
       auth_control_file from OpenVPN side, or -1 if we've already
       written the file. */
    int final_response_fd;

    /* Value is set if success1 is set and final_response_fd is -1.
       The character we wrote to the auth_control_file, or '\0' if
       something went wrong. */
    char final_response_char;

    /* Primary request has been made successfully (OpenVPN side). */
    bool success1;

    /* Set if there is a challenge request that's been suspended
       because the primary OpenVPN authentication hasn't arrived
       yet. */
    struct MHD_Connection *challenge_conn;
    void *challenge_conn_closure;

    char *user;
    struct timespec deadline;

    char *userkey;
    int userkeysize;
    char *keyhandle;

    char *origin;

    /* Secondary challenge/response passed (2F server side). */
    bool success2;
};

enum twofserver_ChallengeResultType {
    /* Auth challenge is being provided as usual. */
    TWOFSERVER_CHALLENGE_PROVIDED,

    /* 2FA not enabled for this request and not required. No challenge. */
    TWOFSERVER_CHALLENGE_UNNECESSARY,

    /* Register on first use is occurring for this request. No challenge. */
    TWOFSERVER_CHALLENGE_REGISTRATION_REQUIRED
};

struct twofserver_PendingAuth *twofserver_new_pending_auth(twofserver_TxnId id);
void twofserver_discard_pending_auth(struct twofserver_PendingAuth *record);
void twofserver_queue_pending_auth(struct twofserver_PendingAuth *record);

struct twofserver_PendingAuth *twofserver_lock_pending_auth(twofserver_TxnId id);
void twofserver_unlock_pending_auth(struct twofserver_PendingAuth *record);

const char *twofserver_challenge_for_auth(struct twofserver_PendingAuth *record,
                                          enum twofserver_ChallengeResultType *chaltype);
bool twofserver_check_auth_response(struct twofserver_PendingAuth *record,
                                    const char *response, size_t response_len);
void twofserver_pass_pending_auth(struct twofserver_PendingAuth *record);
void twofserver_fail_pending_auth(struct twofserver_PendingAuth *record);

bool twofserver_already_registered(struct twofserver_PendingAuth *record);
bool twofserver_can_register(struct twofserver_PendingAuth *record);
const char *twofserver_challenge_for_reg(struct twofserver_PendingAuth *record);
bool twofserver_check_reg_response(struct twofserver_PendingAuth *record,
                                   const char *response, size_t response_len);
void twofserver_process_reg(struct twofserver_PendingAuth *record);

int64_t getCurrentTimestamp();

#endif /* !TWOFSERVER_STATE_H */
