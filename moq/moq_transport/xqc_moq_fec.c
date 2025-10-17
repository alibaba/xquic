#include "moq/moq_transport/xqc_moq_fec.h"

void
xqc_init_quic_fec(xqc_moq_stream_t *moq_stream)
{
    xqc_stream_t *quic_stream = moq_stream->trans_ops.quic_stream(moq_stream->trans_stream);
    if (quic_stream == NULL) {
        return;
    }

    quic_stream->stream_fec_ctl.enable_fec = 1;
    quic_stream->stream_fec_ctl.fec_code_rate = moq_stream->fec_code_rate;
}