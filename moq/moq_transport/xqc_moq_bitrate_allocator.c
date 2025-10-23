
#include "moq/moq_transport/xqc_moq_bitrate_allocator.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_send_ctl.h"

#include <stdio.h>

void 
xqc_moq_delay_set_insert(xqc_moq_delay_data_set_t *data_set, xqc_usec_t ts, xqc_usec_t delay)
{
    data_set->delay_point[data_set->head].ts = ts;
    data_set->delay_point[data_set->head].delay = delay;
    data_set->head = (data_set->head + 1) % XQC_MOQ_DELAY_DATA_SIZE;
    
    if (data_set->count < XQC_MOQ_DELAY_DATA_SIZE) {
        data_set->count++;
    } else {
        data_set->tail = (data_set->tail + 1) % XQC_MOQ_DELAY_DATA_SIZE;
    }
}

void 
xqc_moq_delay_set_clear(xqc_moq_delay_data_set_t *data_set)
{
    xqc_memset(data_set, 0, sizeof(*data_set));
}

xqc_int_t 
xqc_moq_delay_set_is_full(xqc_moq_delay_data_set_t *data_set)
{
    return data_set->count == XQC_MOQ_DELAY_DATA_SIZE;
}

xqc_moq_linear_model_t 
xqc_moq_delay_set_train(xqc_moq_delay_data_set_t *data_set)
{
    xqc_moq_linear_model_t model;
    xqc_memset(&model, 0, sizeof(xqc_moq_linear_model_t));
    xqc_usec_t epoch_start = data_set->delay_point[data_set->tail].ts;
    xqc_int_t index = data_set->tail;
    xqc_moq_data_point_t point;
    double max_y = 0.0;
    
    xqc_moq_linear_train_start(&model);
    
    for (xqc_int_t i = 0; i < data_set->count; i++) {
        point.x = (double)((int64_t)data_set->delay_point[index].ts - (int64_t)epoch_start) / 1000000.0;
        point.y = (double)data_set->delay_point[index].delay / 1000000.0;
        xqc_moq_linear_train_step(&model, point);

        max_y = xqc_max(max_y, point.y);
        
        index = (index + 1) % XQC_MOQ_DELAY_DATA_SIZE;
        if (data_set->count != XQC_MOQ_DELAY_DATA_SIZE && index >= data_set->head) {
            break;
        }
    }
    
    xqc_moq_linear_train_end(&model);
    if (max_y > 0.0) {
        model.slope = model.slope / max_y;
        model.intercept = model.intercept / max_y;
    }
    
    return model;
}

void 
xqc_moq_init_bitrate(xqc_moq_session_t *session)
{
    xqc_moq_bitrate_allocator_t *bitrate_alloc = &session->bitrate_allocator;
    bitrate_alloc->init_bitrate = 1000000; // 1mbps
    bitrate_alloc->max_bitrate = 8000000; // 8mbps
    bitrate_alloc->min_bitrate = 1000000; // 1mbps
    bitrate_alloc->target_bitrate = bitrate_alloc->init_bitrate;
    bitrate_alloc->target_bandwidth = bitrate_alloc->init_bitrate;
}

void
xqc_moq_configure_bitrate(xqc_moq_session_t *session, uint64_t init_bitrate, uint64_t max_bitrate, uint64_t min_bitrate)
{
    xqc_moq_bitrate_allocator_t *bitrate_alloc = &session->bitrate_allocator;
    if (init_bitrate > 0) {
        bitrate_alloc->init_bitrate = init_bitrate;
    }
    if (max_bitrate >= min_bitrate && min_bitrate > 0) {
        bitrate_alloc->max_bitrate = max_bitrate;
        bitrate_alloc->min_bitrate = min_bitrate;
    }
    bitrate_alloc->target_bitrate = bitrate_alloc->init_bitrate;
    xqc_log(session->log, XQC_LOG_INFO, "|v1113|init_bitrate:%ui|max_bitrate:%ui|min_bitrate:%ui|", 
            init_bitrate, max_bitrate, min_bitrate);
}

#define TARGET_DELAY 0.150
#define MAX_SLOPE_THRESHOLD 1.50
#define MIN_SLOPE_THRESHOLD 1.00

static double 
xqc_moq_calculate_slope_threshold(double current_delay) 
{
    double remaining_delay = TARGET_DELAY - current_delay;
    double k = (MAX_SLOPE_THRESHOLD - MIN_SLOPE_THRESHOLD) / TARGET_DELAY;
    double slope_threshold = k * remaining_delay + MIN_SLOPE_THRESHOLD;
    
    if (slope_threshold > MAX_SLOPE_THRESHOLD) {
        slope_threshold = MAX_SLOPE_THRESHOLD;
    } else if (slope_threshold < MIN_SLOPE_THRESHOLD) {
        slope_threshold = MIN_SLOPE_THRESHOLD;
    }

    return slope_threshold;
}

#define BITRATE_DECREASE_FACTOR          (0.85)
#define BITRATE_INCREASE_FACTOR_HIGH     (1.15)
#define BITRATE_INCREASE_FACTOR_MED      (1.05)
#define BITRATE_INCREASE_FACTOR_LOW      (1.02)
#define BITRATE_DECREASE_INTERVAL        (1000000)
#define BITRATE_INCREASE_INTERVAL        (1000000)
#define DELAY_THRESHOLD_MAX              (150000)
#define DELAY_THRESHOLD_MEDIUM           (100000)
#define DELAY_THRESHOLD_MIN              (10000)
#define DELAY_OVER_THRESHOLD             (2)
#define DELAY_UNDER_THRESHOLD            (10)
#define MAX_FEC_CODE_RATE                (20)

double
xqc_moq_est_get_target_fec_code_rate(xqc_connection_t *conn, uint64_t ori_bandwidth, float *fec_code_rate)
{
    double res_rate, one_rpr_rate;
    uint32_t fec_block_size;
    xqc_int_t est_rpr_num, est_src_num;

    *fec_code_rate = 1.0 * xqc_min(MAX_FEC_CODE_RATE, xqc_conn_recent_loss_rate(conn)) / 100.0;
    res_rate = *fec_code_rate;

    return res_rate;
}

uint64_t
xqc_moq_target_bitrate(xqc_moq_session_t *session)
{
    xqc_moq_bitrate_allocator_t *bitrate_alloc = &session->bitrate_allocator;
    xqc_connection_t   *conn;
    float               fec_code_rate;

    conn = session->trans_conn;
    if (bitrate_alloc->target_bandwidth == 0) {
        bitrate_alloc->target_bandwidth = bitrate_alloc->init_bitrate;
    }

    // target bitrate is equal to target bandwidth if there's no repair data
    bitrate_alloc->target_bitrate = bitrate_alloc->target_bandwidth;

    // reserve payload for fec redundant data, based on the assumption that xqc_moq_target_bitrate only used for fec-protected frame.
    if (session->enable_fec) {
        fec_code_rate = xqc_moq_est_get_target_fec_code_rate(conn, bitrate_alloc->target_bitrate, &session->fec_code_rate);
        bitrate_alloc->target_bitrate = bitrate_alloc->target_bandwidth / (1 + fec_code_rate);
        xqc_log(session->log, XQC_LOG_INFO, "|quic_test|code_rate:%.3f|saving bitrate: %ud|original bitrate: %ud|", fec_code_rate, bitrate_alloc->target_bandwidth - bitrate_alloc->target_bitrate, bitrate_alloc->target_bandwidth);
    }

finish:
	bitrate_alloc->target_bitrate =
		xqc_min(bitrate_alloc->max_bitrate, bitrate_alloc->target_bitrate);
	bitrate_alloc->target_bitrate =
		xqc_max(bitrate_alloc->min_bitrate, bitrate_alloc->target_bitrate);

    return bitrate_alloc->target_bitrate;
}

void 
xqc_moq_bitrate_alloc_on_frame_acked(xqc_moq_session_t *session, xqc_usec_t delay, 
    xqc_usec_t create_time, xqc_usec_t now, uint64_t stream_len, uint64_t seq_num)
{
    float fec_code_rate;
    xqc_moq_bitrate_allocator_t *bitrate_alloc = &session->bitrate_allocator;
    
    uint64_t est_bw = xqc_send_ctl_get_est_bw(session->quic_conn->conn_initial_path->path_send_ctl) * 8;
    
    bitrate_alloc->latest_delay = delay;
    xqc_moq_delay_set_insert(&session->bitrate_allocator.delay_data_set, create_time, delay);
    
    if (bitrate_alloc->target_bandwidth == 0) {
        bitrate_alloc->target_bandwidth = bitrate_alloc->init_bitrate;
    }
    
    xqc_moq_linear_model_t model;
    xqc_memset(&model, 0, sizeof(xqc_moq_linear_model_t));
    xqc_int_t is_model_done = 0;
    if (xqc_moq_delay_set_is_full(&session->bitrate_allocator.delay_data_set)) {
        model = xqc_moq_delay_set_train(&session->bitrate_allocator.delay_data_set);
        is_model_done = 1;
    }
    
    double threshold = xqc_moq_calculate_slope_threshold((double)bitrate_alloc->latest_delay / 1000000.0);
    
	if (is_model_done == 0) {
		bitrate_alloc->target_bandwidth = est_bw * 0.8;
		goto finish;
	}

    if (bitrate_alloc->latest_delay > DELAY_THRESHOLD_MAX 
        || (bitrate_alloc->latest_delay > DELAY_THRESHOLD_MEDIUM && is_model_done 
            && model.slope > threshold && model.slope > bitrate_alloc->prev_slope)) 
    {
        bitrate_alloc->delay_under_cnt = 0;
        bitrate_alloc->delay_over_cnt++;
        bitrate_alloc->prev_slope = model.slope;
        
        if (bitrate_alloc->delay_over_cnt >= DELAY_OVER_THRESHOLD
            && now > bitrate_alloc->last_bitrate_decrease_time + BITRATE_DECREASE_INTERVAL) 
        {
            bitrate_alloc->bitrate_threshold = bitrate_alloc->target_bandwidth;
			bitrate_alloc->target_bandwidth = bitrate_alloc->target_bandwidth * BITRATE_DECREASE_FACTOR;
            
            bitrate_alloc->delay_over_cnt = 0;
            bitrate_alloc->prev_slope = 0.0;
            bitrate_alloc->last_bitrate_change_time = now;
            bitrate_alloc->last_bitrate_decrease_time = now;
        }
    } else if (bitrate_alloc->latest_delay <= DELAY_THRESHOLD_MIN
               || (bitrate_alloc->latest_delay <= DELAY_THRESHOLD_MEDIUM && is_model_done 
                   && model.slope < threshold && model.slope > -threshold))
    {
        bitrate_alloc->delay_over_cnt = 0;
        bitrate_alloc->delay_under_cnt++;
        bitrate_alloc->prev_slope = 0.0;
        
        if (bitrate_alloc->delay_under_cnt >= DELAY_UNDER_THRESHOLD
            && now > bitrate_alloc->last_bitrate_change_time + BITRATE_INCREASE_INTERVAL) 
        {
            if (bitrate_alloc->target_bandwidth < bitrate_alloc->bitrate_threshold) {
				bitrate_alloc->target_bandwidth = bitrate_alloc->target_bandwidth * BITRATE_INCREASE_FACTOR_MED;
				
            } else {
				bitrate_alloc->target_bandwidth = est_bw * 0.8;
                
            }
            
            bitrate_alloc->delay_under_cnt = 0;
            bitrate_alloc->last_bitrate_change_time = now;
            bitrate_alloc->last_bitrate_increase_time = now;
        }
    } else {
        bitrate_alloc->delay_over_cnt = 0;
        bitrate_alloc->delay_under_cnt = 0;
        bitrate_alloc->prev_slope = 0.0;
    }

finish:

    // if FEC enabled, save bandwidth for repair packets
    if (XQC_UNLIKELY(session->enable_fec && session->fec_code_rate > 0)) {
        // TODOfec: session may include data frame that does not enable fec, should all the bitrate be estimated using fec_code_rate? fec_code_rate may changed when data frame acked, which rate should be chosen?
        fec_code_rate = session->fec_code_rate;
        bitrate_alloc->target_bitrate = bitrate_alloc->target_bandwidth / (1 + fec_code_rate);
        xqc_log(session->log, XQC_LOG_INFO, "|quic_test|fec_code_rate:%.3f", fec_code_rate);

    } else {
        bitrate_alloc->target_bitrate = bitrate_alloc->target_bandwidth;
    }

    bitrate_alloc->target_bitrate =
		xqc_min(bitrate_alloc->max_bitrate, bitrate_alloc->target_bitrate);
	bitrate_alloc->target_bitrate =
		xqc_max(bitrate_alloc->min_bitrate, bitrate_alloc->target_bitrate);
    
    if (bitrate_alloc->target_bitrate != bitrate_alloc->prev_target_bitrate) {
        if (session->session_callbacks.on_bitrate_change) {
            session->session_callbacks.on_bitrate_change(session->user_session, bitrate_alloc->target_bitrate);
            xqc_log(session->log, XQC_LOG_INFO, "|on_bitrate_change|prev:%ui|now:%ui|", bitrate_alloc->prev_target_bitrate, bitrate_alloc->target_bitrate);
        }
    }
    bitrate_alloc->prev_target_bitrate = bitrate_alloc->target_bitrate;
    
    xqc_log(session->log, XQC_LOG_INFO,
            "|seq:%ui|est_bw:%ui|target_bitrate:%ui|delay_under_cnt:%d|delay_over_cnt:%d|"
            "len:%ui|latest_delay:%ui|slope:%.4f|threshold:%.4f|",
            seq_num, est_bw, bitrate_alloc->target_bitrate, bitrate_alloc->delay_under_cnt, bitrate_alloc->delay_over_cnt,
            stream_len, bitrate_alloc->latest_delay / 1000, model.slope, threshold);
}