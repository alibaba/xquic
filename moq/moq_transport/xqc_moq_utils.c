
#include "moq/moq_transport/xqc_moq_utils.h"
#include "src/common/xqc_time.h"
#include "src/common/xqc_str.h"

void
xqc_moq_fps_counter_insert(xqc_moq_fps_counter_t *counter, xqc_usec_t timestamp)
{
    counter->timestamps[counter->head] = timestamp;
    counter->head = (counter->head + 1) % XQC_MOQ_FPS_COUNTER_BUFFER_SIZE;

    if (counter->count < XQC_MOQ_FPS_COUNTER_BUFFER_SIZE) {
        counter->count++;
    } else {
        counter->tail = (counter->tail + 1) % XQC_MOQ_FPS_COUNTER_BUFFER_SIZE;
    }
}

int
xqc_moq_fps_counter_get(xqc_moq_fps_counter_t *counter, xqc_usec_t timestamp, xqc_usec_t time_window)
{
    int count = 0;
    int index = (counter->head + XQC_MOQ_FPS_COUNTER_BUFFER_SIZE - 1) % XQC_MOQ_FPS_COUNTER_BUFFER_SIZE;
    
    for (int i = 0; i < counter->count; i++) {
        if (timestamp - counter->timestamps[index] <= time_window + 1000) {
            count++;
        } else {
            break;
        }
        index = (index + XQC_MOQ_FPS_COUNTER_BUFFER_SIZE - 1) % XQC_MOQ_FPS_COUNTER_BUFFER_SIZE;
    }
    return count;
}


void 
xqc_moq_linear_train_start(xqc_moq_linear_model_t *model)
{
    xqc_memset(model, 0, sizeof(*model));
}

void 
xqc_moq_linear_train_step(xqc_moq_linear_model_t *model, xqc_moq_data_point_t data)
{
    model->sum_x += data.x;
    model->sum_y += data.y;
    model->sum_xy += data.x * data.y;
    model->sum_xx += data.x * data.x;
    model->n++;
}

void 
xqc_moq_linear_train_end(xqc_moq_linear_model_t *model)
{
    if (model->n * model->sum_xx - model->sum_x * model->sum_x == 0 || model->n == 0) {
        return;
    }
    model->slope = (model->n * model->sum_xy - model->sum_x * model->sum_y) 
                   / (model->n * model->sum_xx - model->sum_x * model->sum_x);
    model->intercept = (model->sum_y - model->slope * model->sum_x) / model->n;
}

void 
xqc_moq_linear_train_model(xqc_moq_linear_model_t *model, xqc_moq_data_point_t *data, xqc_int_t n) 
{
    xqc_moq_linear_train_start(model);
    
    for (xqc_int_t i = 0; i < n; i++) {
        xqc_moq_linear_train_step(model, data[i]);
    }
    
    xqc_moq_linear_train_end(model);
}

double 
xqc_moq_linear_predict(xqc_moq_linear_model_t *model, double x) 
{
    return model->slope * x + model->intercept;
}
