/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the QUIC-LB connection ID encryption of
 * draft-ietf-quic-load-balancers-13 Section 4.3, which a server can use to
 * generate its connection IDs. XQUIC has no QUIC-LB decoder: it only
 * encrypts.
 *
 * The input is the length of the encrypted part, a 16-byte key and the
 * connection ID: a first octet and the plaintext. The encryption must be
 * deterministic and must write nothing past the connection ID.
 */

#include <stdlib.h>
#include <string.h>

#include "src/transport/xqc_engine.h"
#include "xqc_fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static xqc_engine_t *xqc_fuzz_engine;


int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t tcbs;
    xqc_config_t config;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);
    memset(&tcbs, 0, sizeof(tcbs));

    xqc_fuzz_engine_config(&config, XQC_ENGINE_SERVER);

    xqc_fuzz_engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl_config,
                                        &callbacks, &tcbs, NULL);
    if (xqc_fuzz_engine == NULL) {
        abort();
    }

    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    const uint8_t *key, *cid;
    uint8_t *key_buf, *cid_buf, *out1, *out2;
    size_t enc_len, cid_len;

    enc_len = xqc_fuzz_u8(&in) % XQC_MAX_CID_LEN;
    if (xqc_fuzz_take(&in, XQC_LB_CID_KEY_LEN, &key) != XQC_LB_CID_KEY_LEN) {
        return 0;
    }
    cid_len = xqc_fuzz_take(&in, enc_len + 1, &cid);
    if (cid_len != enc_len + 1) {
        return 0;
    }

    /* heap copies of the exact sizes, so that ASan sees overflows */
    key_buf = malloc(XQC_LB_CID_KEY_LEN);
    cid_buf = malloc(cid_len);
    out1 = malloc(cid_len);
    out2 = malloc(cid_len);
    if (key_buf == NULL || cid_buf == NULL || out1 == NULL || out2 == NULL) {
        goto end;
    }
    memcpy(key_buf, key, XQC_LB_CID_KEY_LEN);
    memcpy(cid_buf, cid, cid_len);
    memcpy(out1, cid, cid_len);
    memcpy(out2, cid, cid_len);

    if (xqc_lb_cid_encryption(cid_buf, enc_len, out1, cid_len, key_buf,
                              XQC_LB_CID_KEY_LEN, xqc_fuzz_engine)
            == XQC_OK
        && (xqc_lb_cid_encryption(cid_buf, enc_len, out2, cid_len, key_buf,
                                  XQC_LB_CID_KEY_LEN, xqc_fuzz_engine)
                != XQC_OK
            || memcmp(out1, out2, cid_len) != 0))
    {
        abort();
    }

end:
    free(key_buf);
    free(cid_buf);
    free(out1);
    free(out2);
    return 0;
}
