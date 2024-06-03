/* Portions of this code was adopted from MUNGE https://github.com/dun/munge
 *  Copyright (C) 2007-2024 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2002-2007 The Regents of the University of California.
 *  UCRL-CODE-155910.
 *
 *  See: https://github.com/dun/munge/blob/master/src/munge/munge.c
 *       https://github.com/dun/munge/blob/master/src/munge/unmunge.c
 */
#include "gmunge.h"

conf_t create_conf (void) {
    conf_t conf;

    if (!(conf = malloc (sizeof (struct conf)))) {
		return NULL;
    }

    if (!(conf->ctx = munge_ctx_create ())) {
        free(conf);
		return NULL;
    }

    conf->status = -1;
    conf->cuid = UID_SENTINEL;
    conf->cgid = GID_SENTINEL;
    conf->dlen = 0;
    conf->data = NULL;
    conf->clen = 0;
    conf->cred = NULL;
    return (conf);
}

void * memburn (void *v, int c, size_t n) {
/*  From David A. Wheeler's "Secure Programming for Linux and Unix HOWTO"
 *    <http://www.dwheeler.com/secure-programs/> (section 11.4):
 *  Many compilers, including many C/C++ compilers, remove writes to stores
 *    that are no longer used -- this is often referred to as "dead store
 *    removal".  Unfortunately, if the write is really to overwrite the value
 *    of a secret, this means that code that appears to be correct will be
 *    silently discarded.
 *  One approach that seems to work on all platforms is to write your own
 *    implementation of memset with internal "volatilization" of the first
 *    argument (this code is based on a workaround proposed by Michael Howard):
 */
    volatile char *p = v;

    while (n--) {
        *p++ = c;
    }
    return (v);
}

void destroy_conf (conf_t conf) {
    if (conf->data != NULL) {
        memburn (conf->data, 0, conf->dlen);
        free (conf->data);
        conf->data = NULL;
    }
    if (conf->cred != NULL) {
        memburn (conf->cred, 0, conf->clen);
        free (conf->cred);
        conf->cred = NULL;
    }
    munge_ctx_destroy (conf->ctx);
    free (conf);
    return;
}

int set_opt_int (munge_ctx_t ctx, int opt, int val) {
    return munge_ctx_set (ctx, opt, val);
}

int get_opt_int (munge_ctx_t ctx, int opt, int *val) {
    return munge_ctx_get (ctx, opt, val);
}

int encode_cred (conf_t conf) {
    conf->cuid = geteuid ();
    conf->cgid = getegid ();

    conf->status = munge_encode (&conf->cred, conf->ctx, conf->data, conf->dlen);

    return conf->status;
}

int decode_cred (conf_t conf) {
    conf->status = munge_decode (conf->cred, conf->ctx, &conf->data, &conf->dlen, &conf->cuid, &conf->cgid);
    return conf->status;
}
