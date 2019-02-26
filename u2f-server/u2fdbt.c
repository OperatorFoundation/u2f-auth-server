/* PORTING: crypt_r is a GNU extension... */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "u2fdbt.h"

#include "sha1.h"

struct u2fdbt_FileC {
    struct u2fdbt_File public;

    char *path_buf;
    size_t path_len, path_cap;

    char *line_buf;
    size_t line_len, line_cap;

    /* If 'handle' is NULL, 'stat0' is invalid.  If 'handle' is
       non-null, 'stat0' contains to the original results of fstat on
       its file descriptor. Each time 'handle' is set, 'open_count'
       is incremented; this includes the first time.
     */
    FILE *handle;
    struct stat stat0;
    unsigned open_count;

    struct {
        unsigned open_count;
        long pos;
        bool pos_synced;
        bool eof;
    } scan;

    struct u2fdbt_Record last_record;
};

static int reopen(struct u2fdbt_FileC *filec)
{
    if (filec->handle)
    {
        fclose(filec->handle);
    }

    filec->handle = fopen(filec->path_buf, "ab+");
    if (!filec->handle)
    {
        goto bad;
    }

    filec->open_count++;
    return 0;

bad:
    /* label */ (void)0;
    int saved_errno = errno;

    if (filec->handle != NULL)
    {
        fclose(filec->handle);
    }
    errno = saved_errno;
    return -1;
}

static bool seems_unchanged(const struct stat *old, const struct stat *new)
{
    return (old->st_dev == new->st_dev && old->st_ino == new->st_ino
            && old->st_mtime == new->st_mtime && old->st_size == new->st_size);
}

static int check_reopen(struct u2fdbt_FileC *filec)
{
    if (filec->handle)
    {
        struct stat stat1;
        int err = stat(filec->path_buf, &stat1);
        if (err)
        {
            return -1;
        }

        if (seems_unchanged(&filec->stat0, &stat1))
        {
            return 0;
        }
    }
    
    return reopen(filec);
}

static void destroy(struct u2fdbt_FileC *filec)
{
    free(filec->path_buf);
    filec->path_buf = NULL;
    free(filec->line_buf);
    filec->line_buf = NULL;
    if (filec->handle)
    {
        fclose(filec->handle);
        filec->handle = NULL;
    }
}

struct u2fdbt_File *u2fdbt_open(const char *path)
{
    struct u2fdbt_FileC *filec = calloc(1, sizeof(struct u2fdbt_FileC));
    if (!filec)
    {
        return NULL;
    }

    filec->public.opaque = filec;

    /* One for optional trailing punctuation (used during updates), one
       for the null terminator. */
    filec->path_len = strlen(path);
    filec->path_cap = filec->path_len + 2;
    filec->path_buf = malloc(filec->path_cap);
    if (!filec->path_buf)
    {
        goto oom;
    }

    memcpy(filec->path_buf, path, filec->path_len);
    filec->path_buf[filec->path_len] = '\0';
    filec->path_buf[filec->path_len+1] = '\0';

    /* Note that the line buffer should always have a bounded
       capacity; there are potential integer overflows elsewhere
       prevented by only being able to iterate over a "reasonable"
       number of characters. */
    filec->line_len = 0;
    filec->line_cap = 4096;     /* TODO: doc/move */
    filec->line_buf = malloc(filec->line_cap);
    if (!filec->line_buf)
    {
        goto oom;
    }

    int err = reopen(filec);
    if (err)
    {
        goto badio;
    }

    return &filec->public;

badio:
oom:
    /* label */ (void)0;
    int saved_errno = errno;
    destroy(filec);
    free(filec);
    errno = saved_errno;
    return NULL;
}

/* File handle must be open. */
static char *
fetch_line(struct u2fdbt_FileC *filec)
{
    memset(&filec->last_record, 0, sizeof(filec->last_record));
    char *line = fgets(filec->line_buf, filec->line_cap, filec->handle);
    if (line)
    {
        size_t len = strlen(line);
        if (line[len-1] == '\n')
        {
            line[len-1] = '\0';
            len--;
        }

        filec->line_len = len;
        return line;
    }
    else
    {
        return NULL;
    }
}

static inline int
safe_store_int64_llong(int64_t *p, long long val)
{
#if INT64_MAX < LLONG_MAX
    if ((long long)INT64_MAX < val)
    {
        /* Out of range. */
        return -1;
    }
#endif
#if LLONG_MIN < INT64_MIN
    if (val < (long long)INT64_MIN)
    {
        /* Out of range. */
        return -1;
    }
#endif
    *p = val;
    return 0;
}

/* Comparison function for property keys for qsort. */
static int
property_keycmp_void(const void *a_, const void *b_)
{
    const struct u2fdbt_Property *a = a_;
    const struct u2fdbt_Property *b = b_;
    return strcmp(a->key, b->key);
}

/* TODO: maybe export something like this? */
/* TODO: use strchrnul more in here? */
static int
parse_line(char *line, struct u2fdbt_Record *record)
{
    int saved_errno = errno;
    char *here = line;
    memset(record, 0, sizeof(struct u2fdbt_Record));

    /* Field 1: name */
    record->name = here;
    char *sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;
    }
    else
    {
        goto end;
    }

    /* Field 2: pw_digest */
    record->pw_digest = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;
    }
    else
    {
        goto end;
    }

    /* Field 3: pw_mtime */
    char *pw_mtime_str = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    errno = 0;
    long long pw_mtime_ll = strtoll(pw_mtime_str, &here, 10);
    if (*here != '\0' || errno != 0)
    {
        /* Bad parse. */
        errno = EINVAL;
        goto bad;
    }
    if (safe_store_int64_llong(&record->pw_mtime, pw_mtime_ll))
    {
        /* Out of range. */
        errno = ERANGE;
        goto bad;
    }
    if (!sep)
    {
        goto end;
    }
    here = sep+1;

    /* Field 4: record_mtime */
    char *record_mtime_str = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    errno = 0;
    long long record_mtime_ll = strtoll(record_mtime_str, &here, 10);
    if (*here != '\0' || errno != 0)
    {
        /* Bad parse. */
        errno = EINVAL;
        goto bad;
    }
    if (safe_store_int64_llong(&record->record_mtime, record_mtime_ll))
    {
        /* Out of range. */
        errno = ERANGE;
        goto bad;
    }
    if (!sep)
    {
        goto end;
    }
    here = sep+1;

    /* Field 5: userkey */
    char *userkeyhex = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;

        if(strcmp(userkeyhex, "-")==0)
        {
            record->userkey = NULL;
            record->userkeysize = 0;
        }
        else
        {
            record->userkeysize = strlen(userkeyhex)/2;
            record->userkey=strhex_to_bin(userkeyhex);
        }
    }
    else
    {
        goto end;
    }

    /* Field 6: keyhandle */
    record->keyhandle = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;

        if(strcmp(record->keyhandle, "-")==0)
        {
            record->keyhandle = NULL;
        }
    }
    else
    {
        goto end;
    }

    /* Field 7: flags */
    char *flags_str = here;
    char *unknown_flags_end = flags_str;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    unsigned flags = 0;

    /* Copy known flags into flags bitmask; move unknown
       flags to beginning of flags part of string. */
    while (*here)
    {
        switch (*here)
        {
            /* TODO: these case labels are not being indented right? */
        case 'D':
            flags |= U2FDBT_FLAG_DISABLED;
            break;
        case 'K':
            flags |= U2FDBT_FLAG_HAVE_KEYS;
            break;
        case 'R':
            flags |= U2FDBT_FLAG_REQUIRED;
            break;
        case 'S':
            flags |= U2FDBT_FLAG_SELF_REGISTER;
            break;
        default:
            flags |= U2FDBT_FLAG_UNKNOWN;
            *(unknown_flags_end++) = *here;
            break;
        }

        here++;
    }

    /* The flags_str is now the unknown flags string, the known flags
       having been filtered out. */
    *unknown_flags_end = '\0';
    record->flags = flags;
    record->unknown_flags = flags_str;

    /* Advance past flags field. */
    if (!sep)
    {
        goto end;
    }
    here = sep+1;

    /* Extended properties. */
    struct u2fdbt_Property *plist = malloc(sizeof(struct u2fdbt_Property));
    size_t plist_len = 0, plist_cap = 1;
    if (!plist)
    {
        /* Preserve errno from malloc. */
        goto bad;
    }

    while (*here) {
        const char *key = here;
        while (*here && !(*here == ':' || *here == '='))
            here++;
        if (*here != '=')
        {
            /* Malformed property, no value separator. */
            errno = EINVAL;
            goto bad;
        }

        *here = '\0';
        here++;

        const char *value = here;
        sep = strchr(here, ':');
        if (sep)
        {
            *sep = '\0';
            here = sep+1;
        }
        else
        {
            here = strchr(here, '\0');
        }
    }

end:
    /* TODO: consistency-check record, decide what to do about returning
       inconsistent records, as well as what to do about malformed lines
       and whether that should be consistent? */
    errno = saved_errno;
    return 0;
bad:
    /* TODO: propagating all errno values out of here doesn't work so great
       for detecting what happened in callers */
    return -1;
}

struct u2fdbt_Record *u2fdbt_next(struct u2fdbt_File *file)
{
    struct u2fdbt_FileC *filec = file->opaque;
    if (filec->scan.eof)
    {
        /* Already at EOF. */
        return NULL;
    }

    next_line:
    /* label */ (void)0;
    char *line = fetch_line(filec);
    if (!line)
    {
        if (feof(filec->handle))
        {
            filec->scan.eof = true;
        }

        /* Pass through errno if there was an I/O error in
           fetch_line. Otherwise, it remains unset,
           Unix-style. */
        return NULL;
    }

    int err = parse_line(line, &filec->last_record);
    if (err)
    {
        /* Skip truly malformed lines. This isn't great, but it's a
           little more robust than the alternatives... */
        goto next_line;
    }

    return &filec->last_record;
}

struct u2fdbt_Record *u2fdbt_find(struct u2fdbt_File *file, const char *name)
{
    /* Names can't contain colons. */
    if (strchr(name, ':'))
    {
        errno = EINVAL;
        return NULL;
    }

    struct u2fdbt_FileC *filec = file->opaque;
    int err = check_reopen(filec);
    if (err)
    {
        return NULL;
    }

    filec->scan.pos_synced = false;
    err = fseek(filec->handle, 0, SEEK_SET);
    if (err)
    {
        return NULL;
    }

    size_t name_len = strlen(name);
    char *line;
    while ((line = fetch_line(filec))) {
        if (strncmp(line, name, name_len) == 0
            && (line[name_len] == ':' || line[name_len] == '\0'))
        {
            err = parse_line(line, &filec->last_record);
            if (err)
            {
                /* TODO: probably shouldn't propagate errno */
                return NULL;
            }
            else
            {
                /* Found it. Make sure our original condition was
                   okay. Note that if the name contained a colon,
                   we already caught this above. */
                assert(!strcmp(filec->last_record.name, name));
                return &filec->last_record;
            }
        }
    }

    if (!ferror(filec->handle))
    {
        /* No I/O error, there just weren't any more lines.
           So, the name wasn't found. TODO: this error reporting
           though... */
        errno = ENOENT;
    }
    return NULL;
}

void
u2fdbt_close(struct u2fdbt_File *file)
{
    struct u2fdbt_FileC *filec = file->opaque;
    FILE *f=filec->handle;
    int fd=fileno(f);

    fflush(f);
    fsync(fd);

    destroy(filec);
    free(filec);
}

int u2fdbt_begin_update(struct u2fdbt_File *file)
{
    // FIXME - We should do atomic updates to prevent the obvious problems with simultaneous access.
    return 1;
}

int u2fdbt_finish_update(struct u2fdbt_File *file)
{
    // FIXME - We should do atomic updates to prevent the obvious problems with simultaneous access.
    return 1;
}

int u2fdbt_delete_user(struct u2fdbt_File *oldfile, const char *name)
{
    struct u2fdbt_File *newfile=u2fdbt_open("tmp.dbt");

    struct u2fdbt_Record *record=u2fdbt_next(oldfile);
    while(record!=NULL)
    {
        if(!strcmp(record->name, name))
        {
            write_record(newfile, record);
        }

        record=u2fdbt_next(oldfile);
    }

    u2fdbt_close(newfile);

    struct u2fdbt_FileC *oldfilec=(struct u2fdbt_FileC *)oldfile->opaque;
    struct u2fdbt_FileC *newfilec=(struct u2fdbt_FileC *)newfile->opaque;

    rename("tmp.dbt", oldfilec->path_buf);

    return 1;
}

int u2fdbt_append_new(struct u2fdbt_File *file, struct u2fdbt_Record *new_record)
{
    struct u2fdbt_Record *record=u2fdbt_find(file, new_record->name);

    if(record==NULL)
    {
        write_record(file, new_record);
        return 1;
    }
    else
    {
        return 0;
    }
}

int u2fdbt_replace(struct u2fdbt_File *file, struct u2fdbt_Record *record)
{
    struct u2fdbt_Record new_record;
    memcpy(&new_record, record, sizeof(struct u2fdbt_Record));

    struct u2fdbt_Record *old_record=u2fdbt_find(file, record->name);

    if(old_record==NULL)
    {
        // Cannot replace user, as user does not exist.
        return 0;
    }
    else
    {
        u2fdbt_delete_user(file, new_record.name);
        u2fdbt_append_new(file, &new_record);

        return 1;
    }
}

bool u2fdbt_digest_accepts_password(const char *digest, const char *password)
{
    if (digest[0] == '-' && digest[1] == '\0')
    {
        /* Top accepts all passwords. */
        return true;
    }
    else if (digest[0] == '*' && digest[1] == '\0')
    {
        /* Bottom never accepts any passwords. */
        return false;
    }
    else if (strlen(digest)==40)
    {
        unsigned char *hash=hash_password(password);

        return memcmp(hash, digest, 40) == 0;
    }
    else
    {
        errno = ERANGE;
        return false;
    }
}

unsigned char *hash_password(const char *password)
{
    SHA1_CTX sha;
    uint8_t result[20];
    unsigned char *hexed;

    SHA1Init(&sha);
    SHA1Update(&sha, (uint8_t *)password, strlen(password));
    SHA1Final(result, &sha);
    bin_to_strhex((const unsigned char *)result, 20, &hexed);

    return hexed;
}

unsigned char *bin_to_strhex(const unsigned char *bin, unsigned int binsz, unsigned char **result)
{
    unsigned char     hex_str[]= "0123456789abcdef";
    unsigned int      i;

    if (!(*result = (unsigned char *)malloc(binsz * 2 + 1)))
        return (NULL);

    (*result)[binsz * 2] = 0;

    if (!binsz)
        return (NULL);

    for (i = 0; i < binsz; i++)
    {
        (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }
    return (*result);
}

const char *strhex_to_bin(char *string)
{
    if(string == NULL)
        return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0) // must be even
        return NULL;

    size_t dlength = slength / 2;

    char *data = malloc(dlength);
    memset((void *)data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            free((void *)data);
            return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return (const char *)data;
}

static int write_record(struct u2fdbt_File *file, struct u2fdbt_Record *record)
{
    struct u2fdbt_FileC *filec = file->opaque;
    int err = check_reopen(filec);
    if (err)
    {
        return 0;
    }

    filec->scan.pos_synced = false;
    err = fseek(filec->handle, 0, SEEK_END);
    if (err)
    {
        return 0;
    }

    FILE *f = filec->handle;

    /* Field 1: name */
    fprintf(f, "%s:", record->name);

    /* Field 2: pw_digest */
    fprintf(f, "%s:", record->pw_digest);

    /* Field 3: pw_mtime */
    fprintf(f, "%llu:", record->pw_mtime);

    /* Field 4: record_mtime */
    fprintf(f, "%llu:", record->record_mtime);

    /* Field 5: userkey */
    if(record->userkey==NULL)
    {
        fprintf(f, "-:");
    }
    else
    {
        unsigned char *userkeyhex=malloc(record->userkeysize*2 + 1);
        bin_to_strhex((const unsigned char *)record->userkey, record->userkeysize, &userkeyhex);
        userkeyhex[record->userkeysize*2]='\0';
        fprintf(f, "%s:", userkeyhex);
    }

    /* Field 5: keyhandle */
    if(record->keyhandle==NULL)
    {
        fprintf(f, "-:");
    }
    else
    {
        fprintf(f, "%s:", record->keyhandle);
    }

    /* Field 7: flags */
    if(record->flags & U2FDBT_FLAG_DISABLED)
    {
        fprintf(f, "D");
    }

    if (record->flags & U2FDBT_FLAG_HAVE_KEYS)
    {
        fprintf(f, "K");
    }

    if (record->flags & U2FDBT_FLAG_REQUIRED)
    {
        fprintf(f, "R");
    }

    if (record->flags & U2FDBT_FLAG_SELF_REGISTER)
    {
        fprintf(f, "S");
    }

    // FIXME - write registered key

    fprintf(f, "\n");

    return 1;
}
