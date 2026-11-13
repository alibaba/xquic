/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Helpers shared by the libFuzzer targets of tests/fuzz.
 */

#ifndef XQC_FUZZ_COMMON_H
#define XQC_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

#include "src/common/xqc_log.h"

/* the start of the virtual clock of every input, in microseconds */
#define XQC_FUZZ_START_TIME  ((xqc_usec_t)1700000000 * 1000000)

/* a cursor over the input; reads past its end return zeros */
typedef struct xqc_fuzz_input_s {
    const uint8_t *data;
    size_t size;
} xqc_fuzz_input_t;

uint8_t xqc_fuzz_u8(xqc_fuzz_input_t *in);
uint16_t xqc_fuzz_u16(xqc_fuzz_input_t *in);
uint64_t xqc_fuzz_u64(xqc_fuzz_input_t *in);

/* take up to max bytes from the input, return how many were taken */
size_t xqc_fuzz_take(xqc_fuzz_input_t *in, size_t max, const uint8_t **out);

/* take a length-prefixed chunk (16-bit length, cut to what is left) */
size_t xqc_fuzz_chunk(xqc_fuzz_input_t *in, const uint8_t **out);

/* the virtual clock; xqc_fuzz_time() is the engines' time callback */
extern xqc_usec_t xqc_fuzz_now;
xqc_usec_t xqc_fuzz_time(void);

/*
 * fill callbacks with a virtual clock, a timer callback that does nothing
 * and log callbacks that drop every line
 */
void xqc_fuzz_engine_callbacks(xqc_engine_callback_t *callbacks);

/*
 * the log level of the engines, from XQC_FUZZ_LOG_LEVEL: 0 (the default)
 * only formats the report lines, 6 formats every debug line and qlog event
 */
xqc_log_level_t xqc_fuzz_log_level(void);

/*
 * the default configuration of an engine type, with the log level of the
 * targets and hash tables and queues sized for a few connections: the
 * server default allocates and clears tens of megabytes per engine
 */
void xqc_fuzz_engine_config(xqc_config_t *config, xqc_engine_type_t type);

/* a log that drops every line, for the modules driven without an engine */
xqc_log_t *xqc_fuzz_log(void);

/*
 * fill an engine TLS configuration with a key and a self-signed
 * certificate made once per process
 */
void xqc_fuzz_ssl_config(xqc_engine_ssl_config_t *ssl_config);

#endif /* XQC_FUZZ_COMMON_H */
