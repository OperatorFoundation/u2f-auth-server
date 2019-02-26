#ifndef U2FDBT_H
#define U2FDBT_H 1

#include <stdint.h>
#include <stdbool.h>

struct u2fdbt_File {
    /* Opaque pointer owned by the library. */
    void *opaque;
};

enum {
    /* Disabled flag 'D': second-factor authentication is not enabled
       for this account.
    */
    U2FDBT_FLAG_DISABLED = 1u << 1,

    /* Have-keys flag 'K': at least one U2F key is registered on this
       account. This flag must be set when and only when the record
       has at least one property with a key matching the glob
       "u2fkey.*".
    */
    U2FDBT_FLAG_HAVE_KEYS = 1u << 2,

    /* Required flag 'R': second factor is required for authentication.
       Otherwise, the second factor is optional.
    */
    U2FDBT_FLAG_REQUIRED = 1u << 3,

    /* Self-register flag 'S': authenticating successfully allows
       registration of new keys in-band.
    */
    U2FDBT_FLAG_SELF_REGISTER = 1u << 4,

    /* This flag is set if any unknown flag characters are encountered in
       the record. In that case, the unknown_flags field of the record
       struct contains all the unknown flags characters.
    */
    U2FDBT_FLAG_UNKNOWN = 1u << 0
};

/* String key-value pair for one extended property of one record. */
struct u2fdbt_Property {
    const char *key;
    const char *value;
};

/* Structure representing one record in a U2FDBT database.

   A record pointer returned by a read operation (mainly u2fdbt_next
   or u2fdbt_find) on a u2fdbt_File remains valid until the next read
   or write operation; this also applies to all memory it points
   to. It must not be used after the next read or write operation. If
   you wish to retain a copy of the record, you can use
   u2fdbt_record_dup.
 */
struct u2fdbt_Record {
    /* Username, theoretically UTF-8. May not contain ':'. */
    const char *name;

    /* Password digest, ASCII, self-describing. May not contain ':'.

       If a digest begins with '$' and an ASCII digit, it is in glibc
       extended crypt() format; in particular, "$1" is MD5-based, "$5"
       is SHA-256-based, and "$6" is SHA-512-based.

       If a digest is exactly "-" (Top), any password is valid; the user
       either authenticates using some other mechanism as the first
       factor, or uses the security key as the only factor. No other
       valid digest strings will ever begin with '-'.

       If a digest is exactly "*" (Bottom), all passwords are
       invalid; no authentication for this user against this database
       can succeed.  No other valid digest strings will ever begin
       with '*'.

       All other digest strings are reserved.
     */
    const char *pw_digest;

    /* Unix timestamp of last password change, or 0 for unknown. */
    int64_t pw_mtime;

    /* Unix timestamp of last update to this record, or 0 for unknown. */
    int64_t record_mtime;

    /* Inclusive-or of flag bits above. */
    unsigned flags;

    /* An unsorted string of ASCII characters corresponding to all
       unknown flags set. May not contain ':'. This string must be of
       nonzero length when and only when U2FDBT_FLAG_UNKNOWN is set in
       the flags field. It must never be a null pointer.
    */
    const char *unknown_flags;

    // Bytes with length
    const char *userkey;
    int userkeysize;

    // Encoded as ASCII, stored in a C string
    const char *keyhandle;

    /* Opaque pointer owned by the library. */
    void *opaque;
};

/* TODO: u2fdbt_check_password */

/* Open a U2FDBT database at PATH, initially for reading only. The
   underlying file must not be modified in-place while it is open;
   database updates must be performed by replacing the file using the
   specific update procedure documented in u2fdbt_begin_update. For
   behavior if an update procedure occurs during an operation, look at
   the documentation for the specific operation.

   Note that because of this replacement behavior, a u2fdbt_File is
   not necessarily persistently associated with one underlying file
   handle or file descriptor, but with the path. Moving the file
   externally while it is in use may result in unpredictable behavior;
   it should only be replaced via the update functions below.

   Files in the same directory which have a name consisting of the
   original file name followed by a single punctuation character are
   reserved for the use of update procedures and should not be used
   for unrelated purposes.

   This is like Unix 'setpwent' called for the first time.
*/
struct u2fdbt_File *u2fdbt_open(const char *path);

/* Find, parse, and return the record for NAME in FILE. The seek
   position of FILE is unchanged. If an update procedure on FILE
   completes between calls to u2fdbt_find, this function will only
   consider records from the new version of the file.

   This is like Unix 'getpwnam'.

   If there are somehow multiple records in FILE corresponding to
   NAME, one of them will be returned, but which one is unspecified.
   If there are multiple records, some of which are recognized as
   potentially valid and some of which are recognized as invalid,
   either one of the potentially valid records will be returned or an
   appropriate error for one of the invalid records will be returned.
*/
struct u2fdbt_Record *u2fdbt_find(struct u2fdbt_File *file, const char *name);
struct u2fdbt_Record *u2fdbt_next(struct u2fdbt_File *file);

/* Close FILE, freeing all resources associated with it. If an update
   procedure has been begun for FILE but not finished, it is aborted
   as if with u2fdbt_abort_update.

   This is like Unix 'endpwent'.
*/
void u2fdbt_close(struct u2fdbt_File *file);

/* Return whether the digest DIGEST accepts the password PASSWORD. */
bool u2fdbt_digest_accepts_password(const char *digest, const char *password);

/* Begin an update of the U2FDBT file FILE. A full update procedure
   consists of the following:

   1. A call to u2fdbt_begin_update to take the update lock and
      prepare to write new records. During an update procedure,
      external replacements of the underlying file are not allowed
      and may cause data corruption.

   2. Zero or more calls to u2fdbt_next to retrieve the original
      records. Each such call must be followed by exactly one call to
      one of the following update functions:

      - u2fdbt_keep_last: The record is kept as-is.
        (That is, it is copied into the set of new records.)
      - u2fdbt_replace_last: The record is replaced with an updated one.
        (That is, the updated record is copied into the set of new records.)
      - u2fdbt_delete_last: The record is deleted.
        (That is, it is not copied into the set of new records.)

      At any time during an update procedure, u2fdbt_insert_new calls may
      also be performed to add new records unrelated to any old record.
      (u2fdbt_replace_last is thus technically a convenience function and
      could be replaced with a u2fdbt_delete_last/u2fdbt_insert_new
      sequence.)

   3. If the seek position was _not_ at end of file after step 2 (you
      stopped calling u2fdbt_next early), exactly one call to one of the
      following functions:

      - u2fdbt_keep_rest: All unread records are kept as-is.
      - u2fdbt_delete_rest: All unread records are deleted.

   4. A call to u2fdbt_finish_update to rotate the new records in to
      replace the old records and release the update lock.

   Another process that begins a read from this file before
   u2fdbt_finish_update is called will perform the read based on the
   original records.

   u2fdbt_abort_update may be used at any time to abort the update
   process and leave the original file unchanged, even if records
   have been marked as changed or deleted already.

   Two update procedures may not be ongoing at the same time; this is
   enforced using POSIX file locks.

   Note that the library itself does not necessarily check for
   duplicate names! If you insert multiple records under the same
   name, which one is retrieved by u2fdbt_find is unspecified.
 */
int u2fdbt_begin_update(struct u2fdbt_File *file);

/* During an update procedure, indicate that NEW_RECORD should be
   included in the updated file. See u2fdbt_begin_update.

   NEW_RECORD will be copied as needed and is not required to remain
   valid beyond the duration of this call.
*/
int u2fdbt_append_new(struct u2fdbt_File *file, struct u2fdbt_Record *new_record);

/* During an update procedure, indicate that RECORD should be
   replaced in the updated file. See u2fdbt_begin_update.

   RECORD will be copied as needed and is not required to remain
   valid beyond the duration of this call.
*/
int u2fdbt_replace(struct u2fdbt_File *file, struct u2fdbt_Record *record);

int u2fdbt_delete_user(struct u2fdbt_File *file, const char *name);

/* Finish an update procedure started by u2fdbt_begin_update. The seek
   pointer must be at end of file. After this function returns
   successfully, subsequent calls to u2fdbt_rewind or u2fdbt_find from
   any process will result in reading from the new set of records.
*/
int u2fdbt_finish_update(struct u2fdbt_File *file);

/* Abort an update procedure started by u2fdbt_begin_update. The seek
   pointer may be anywhere. After this function returns successfully,
   calls to u2fdbt_rewind or u2fdbt_find from any process will continue
   reading the original, unchanged records.
 */
int u2fdbt_abort_update(struct u2fdbt_File *file);

unsigned char *hash_password(const char *password);
unsigned char *bin_to_strhex(const unsigned char *bin, unsigned int binsz, unsigned char **result);
const char *strhex_to_bin(char *string);
static int write_record(struct u2fdbt_File *file, struct u2fdbt_Record *record);


#endif /* !U2FDBT_H */
