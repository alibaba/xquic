/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Helpers shared by the libFuzzer targets of tests/fuzz.
 */

#include "xqc_fuzz_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


xqc_usec_t xqc_fuzz_now = XQC_FUZZ_START_TIME;

static char xqc_fuzz_dir[256];
static char xqc_fuzz_key[300];
static char xqc_fuzz_cert[300];


uint8_t
xqc_fuzz_u8(xqc_fuzz_input_t *in)
{
    uint8_t v;

    if (in->size == 0) {
        return 0;
    }

    v = in->data[0];
    in->data++;
    in->size--;
    return v;
}

uint16_t
xqc_fuzz_u16(xqc_fuzz_input_t *in)
{
    uint16_t v = xqc_fuzz_u8(in);

    return (uint16_t)(v << 8 | xqc_fuzz_u8(in));
}

uint64_t
xqc_fuzz_u64(xqc_fuzz_input_t *in)
{
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++) {
        v = v << 8 | xqc_fuzz_u8(in);
    }

    return v;
}

size_t
xqc_fuzz_take(xqc_fuzz_input_t *in, size_t max, const uint8_t **out)
{
    size_t n = in->size < max ? in->size : max;

    *out = in->data;
    in->data += n;
    in->size -= n;
    return n;
}

size_t
xqc_fuzz_chunk(xqc_fuzz_input_t *in, const uint8_t **out)
{
    return xqc_fuzz_take(in, xqc_fuzz_u16(in), out);
}

xqc_usec_t
xqc_fuzz_time(void)
{
    return xqc_fuzz_now;
}

static void
xqc_fuzz_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
}

static void
xqc_fuzz_write_log(xqc_log_level_t lvl, const void *buf, size_t size,
                   void *engine_user_data)
{
}

static void
xqc_fuzz_write_qlog(qlog_event_importance_t imp, const void *buf, size_t size,
                    void *engine_user_data)
{
}

static xqc_log_callbacks_t xqc_fuzz_log_callbacks = {
    .xqc_log_write_err = xqc_fuzz_write_log,
    .xqc_log_write_stat = xqc_fuzz_write_log,
    .xqc_qlog_event_write = xqc_fuzz_write_qlog,
};

void
xqc_fuzz_engine_callbacks(xqc_engine_callback_t *callbacks)
{
    memset(callbacks, 0, sizeof(*callbacks));
    callbacks->set_event_timer = xqc_fuzz_set_event_timer;
    callbacks->log_callbacks = xqc_fuzz_log_callbacks;
    callbacks->realtime_ts = xqc_fuzz_time;
    callbacks->monotonic_ts = xqc_fuzz_time;
}

xqc_log_level_t
xqc_fuzz_log_level(void)
{
    static int level = -1;
    const char *env;

    if (level < 0) {
        env = getenv("XQC_FUZZ_LOG_LEVEL");
        level = env != NULL ? atoi(env) : XQC_LOG_REPORT;
        if (level < XQC_LOG_REPORT || level > XQC_LOG_DEBUG) {
            level = XQC_LOG_REPORT;
        }
    }

    return (xqc_log_level_t)level;
}

void
xqc_fuzz_engine_config(xqc_config_t *config, xqc_engine_type_t type)
{
    if (xqc_engine_get_default_config(config, type) != XQC_OK) {
        abort();
    }

    config->cfg_log_level = xqc_fuzz_log_level();
    config->cfg_log_event = config->cfg_log_level == XQC_LOG_DEBUG;
    config->streams_hash_bucket_size = 64;
    config->conns_hash_bucket_size = 64;
    config->conns_active_pq_capacity = 16;
    config->conns_wakeup_pq_capacity = 16;
}

xqc_log_t *
xqc_fuzz_log(void)
{
    static xqc_log_t log;

    log.log_level = xqc_fuzz_log_level();
    log.log_event = log.log_level == XQC_LOG_DEBUG;
    log.qlog_importance = EVENT_IMPORTANCE_EXTRA;
    log.log_callbacks = &xqc_fuzz_log_callbacks;
    return &log;
}

static void
xqc_fuzz_remove_files(void)
{
    unlink(xqc_fuzz_key);
    unlink(xqc_fuzz_cert);
    rmdir(xqc_fuzz_dir);
}

/* a P-256 key and a self-signed certificate for test.xquic.com */
static int
xqc_fuzz_make_cert(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    X509_NAME *name;
    FILE *fp;
    const char *tmp;
    int ok = 0;

    tmp = getenv("TMPDIR");
    snprintf(xqc_fuzz_dir, sizeof(xqc_fuzz_dir), "%s/xqc-fuzz-XXXXXX",
             tmp != NULL && tmp[0] != '\0' ? tmp : "/tmp");
    if (mkdtemp(xqc_fuzz_dir) == NULL) {
        return 0;
    }
    snprintf(xqc_fuzz_key, sizeof(xqc_fuzz_key), "%s/key.pem", xqc_fuzz_dir);
    snprintf(xqc_fuzz_cert, sizeof(xqc_fuzz_cert), "%s/cert.pem", xqc_fuzz_dir);
    atexit(xqc_fuzz_remove_files);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)
               <= 0
        || EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        goto end;
    }

    x509 = X509_new();
    if (x509 == NULL || !X509_set_version(x509, 2)
        || !ASN1_INTEGER_set(X509_get_serialNumber(x509), 1)
        || !X509_gmtime_adj(X509_getm_notBefore(x509), -86400)
        || !X509_gmtime_adj(X509_getm_notAfter(x509), 86400L * 3650)
        || !X509_set_pubkey(x509, pkey))
    {
        goto end;
    }

    name = X509_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"test.xquic.com", -1,
                                    -1, 0)
        || !X509_set_issuer_name(x509, name)
        || !X509_sign(x509, pkey, EVP_sha256()))
    {
        goto end;
    }

    fp = fopen(xqc_fuzz_key, "w");
    if (fp == NULL) {
        goto end;
    }
    ok = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    if (fclose(fp) != 0) {
        ok = 0;
    }
    if (!ok) {
        goto end;
    }

    fp = fopen(xqc_fuzz_cert, "w");
    if (fp == NULL) {
        ok = 0;
        goto end;
    }
    ok = PEM_write_X509(fp, x509);
    if (fclose(fp) != 0) {
        ok = 0;
    }

end:
    X509_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

void
xqc_fuzz_ssl_config(xqc_engine_ssl_config_t *ssl_config)
{
    static int made = 0;

    if (!made) {
        if (!xqc_fuzz_make_cert()) {
            fprintf(stderr, "xqc_fuzz: cannot make a test certificate\n");
            abort();
        }
        made = 1;
    }

    memset(ssl_config, 0, sizeof(*ssl_config));
    ssl_config->private_key_file = xqc_fuzz_key;
    ssl_config->cert_file = xqc_fuzz_cert;
    ssl_config->ciphers = XQC_TLS_CIPHERS;
    ssl_config->groups = XQC_TLS_GROUPS;
}
