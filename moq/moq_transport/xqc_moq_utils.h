#ifndef _XQC_MOQ_UTILS_H_INCLUDED_
#define _XQC_MOQ_UTILS_H_INCLUDED_

#include "xquic/xquic_typedef.h"

#define XQC_MOQ_MAX_FPS 90
#define XQC_MOQ_MAX_TIME_WINDOW_S 3
#define XQC_MOQ_FPS_COUNTER_BUFFER_SIZE (XQC_MOQ_MAX_FPS * XQC_MOQ_MAX_TIME_WINDOW_S)

typedef struct {
    xqc_usec_t  timestamps[XQC_MOQ_FPS_COUNTER_BUFFER_SIZE];
    xqc_int_t   head;
    xqc_int_t   tail;
    xqc_int_t   count;
} xqc_moq_fps_counter_t;

void xqc_moq_fps_counter_insert(xqc_moq_fps_counter_t *counter, xqc_usec_t timestamp);

xqc_int_t xqc_moq_fps_counter_get(xqc_moq_fps_counter_t *counter, xqc_usec_t timestamp, xqc_usec_t time_window);


typedef struct {
    double x;
    double y;
} xqc_moq_data_point_t;

typedef struct {
    /* Input */
    double    sum_x;
    double    sum_y;
    double    sum_xy;
    double    sum_xx;
    xqc_int_t n;

    /* Output */
    double    slope;
    double    intercept;
} xqc_moq_linear_model_t;

void xqc_moq_linear_train_start(xqc_moq_linear_model_t *model);

void xqc_moq_linear_train_step(xqc_moq_linear_model_t *model, xqc_moq_data_point_t data);

void xqc_moq_linear_train_end(xqc_moq_linear_model_t *model);

void xqc_moq_linear_train_model(xqc_moq_linear_model_t *model, xqc_moq_data_point_t *data, xqc_int_t n);

double xqc_moq_linear_predict(xqc_moq_linear_model_t *model, double x);


#endif /* _XQC_MOQ_UTILS_H_INCLUDED_ */
