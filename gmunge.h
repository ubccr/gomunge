/* Portions of this code was adopted from MUNGE https://github.com/dun/munge
 *  Copyright (C) 2007-2024 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  See: https://github.com/dun/munge/blob/master/src/munge/munge.c
 *       https://github.com/dun/munge/blob/master/src/munge/unmunge.c
 */
#include <sys/types.h>
#include <unistd.h>
#include <munge.h>
#include <stdlib.h>

#define UID_MAXIMUM     (UINT32_MAX - 1)
#define UID_SENTINEL    ((uid_t) -1)
#define GID_MAXIMUM     (UINT32_MAX - 1)
#define GID_SENTINEL    ((gid_t) -1)

struct conf {
    munge_ctx_t  ctx;                   /* munge context                     */
    munge_err_t  status;                /* error status munging the cred     */
    uid_t        cuid;                  /* credential UID                    */
    gid_t        cgid;                  /* credential GID                    */
    int          dlen;                  /* payload data length               */
    void        *data;                  /* payload data                      */
    int          clen;                  /* munged credential length          */
    char        *cred;                  /* munged credential nul-terminated  */
};

typedef struct conf * conf_t;

conf_t create_conf (void);
int    set_opt_int (munge_ctx_t ctx, int opt, int val);
int    get_opt_int (munge_ctx_t ctx, int opt, int *val);
int    encode_cred (conf_t conf);
int    decode_cred (conf_t conf);
void * memburn (void *v, int c, size_t n);
void   destroy_conf (conf_t conf);
