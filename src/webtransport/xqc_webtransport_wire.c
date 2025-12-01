/**
 * xqc_webtransport_wire.c
 */

#include "xqc_webtransport_wire.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

size_t
xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len)
{
    size_t need = xqc_put_varint_len(session_id);
    if (need == 0 || buf_len < need) {
        return 0;
    }
    (void)xqc_put_varint(buf, session_id);
    return need;
}

ssize_t
xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id)
{
    if (buf == NULL || session_id == NULL || buf_len == 0) {
        return -XQC_EPARAM;
    }

    const uint8_t *end = buf + buf_len;
    int            n   = xqc_vint_read(buf, end, session_id);
    if (n <= 0) {
        return -XQC_H3_DECODE_ERROR;
    }
    return n;
}

