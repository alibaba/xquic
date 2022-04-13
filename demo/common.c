/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "common.h"
#include <stdlib.h>
#include <assert.h>
#include <strings.h>
#include <string.h>


void
xqc_demo_ring_queue_init(xqc_demo_ring_queue_t *ring_queue,
                         size_t element_max_num, size_t element_buf_size)
{
    uint8_t *buf;
    size_t i;
    size_t ele_size;
    assert(ring_queue);

    bzero(ring_queue, sizeof(xqc_demo_ring_queue_t));

    ring_queue->p = malloc(element_max_num * sizeof(xqc_demo_ring_queue_element_t*));
    assert(ring_queue->p);

    ele_size = sizeof(xqc_demo_ring_queue_element_t) + element_buf_size;
    buf = malloc(element_max_num * ele_size);
    assert(buf);

    ring_queue->element_max_num = element_max_num;
    ring_queue->element_buf_size = element_buf_size;

    for (i = 0; i < ring_queue->element_max_num; i++) {
        ring_queue->p[i] = buf + (i * ele_size);
    }
}

void
xqc_demo_ring_queue_free(xqc_demo_ring_queue_t *ring_queue)
{
    if (ring_queue) {
        if (ring_queue->p) {
            if (*ring_queue->p) {
                free(*ring_queue->p);
            }
            free(ring_queue->p);
        }
        bzero(ring_queue, sizeof(xqc_demo_ring_queue_t));
    }
}

// return: 0, ok; 1, queue full; -1 error
int
xqc_demo_ring_queue_push(xqc_demo_ring_queue_t *ring_queue,
                          uint8_t* data_buf, size_t data_size)
{
    if (data_size > ring_queue->element_buf_size) {
        return -1;
    }
    if (ring_queue->element_num >= ring_queue->element_max_num) {
        return 1;
    }
    if (ring_queue->write_idx + 1 >= ring_queue->element_max_num) {
        ring_queue->write_idx = 0;
    } else {
        ring_queue->write_idx++;
    }
    xqc_demo_ring_queue_element_t *ele =
            (xqc_demo_ring_queue_element_t*)(ring_queue->p[ring_queue->write_idx]);
    memcpy(ele->data_buf, data_buf, data_size);
    ele->data_size = data_size;
    ring_queue->element_num++;
    return 0;
}

// return: 0, ok; 1, queue full; -1 error
int
xqc_demo_ring_queue_push2(xqc_demo_ring_queue_t* ring_queue,
                          uint8_t* data_hdr, size_t data_hdr_size,
                          uint8_t* data_body, size_t data_body_size)
{
    if (data_hdr_size + data_body_size > ring_queue->element_buf_size) {
        return -1;
    }
    if (ring_queue->element_num >= ring_queue->element_max_num) {
        return 1;
    }
    xqc_demo_ring_queue_element_t *ele =
            (xqc_demo_ring_queue_element_t*)(ring_queue->p[ring_queue->write_idx]);
    memcpy(ele->data_buf, data_hdr, data_hdr_size);
    memcpy(ele->data_buf + data_hdr_size, data_body, data_body_size);
    ele->data_size = data_hdr_size + data_body_size;
    if (ring_queue->write_idx + 1 >= ring_queue->element_max_num) {
        ring_queue->write_idx = 0;
    } else {
        ring_queue->write_idx++;
    }
    ring_queue->element_num++;
    return 0;
}

// return: 0, ok; 1, queue empty; -1 error
int
xqc_demo_ring_queue_pop(xqc_demo_ring_queue_t *ring_queue,
                        uint8_t* data_buf, size_t buf_size, size_t *out_data_size)
{
    if (ring_queue->element_num == 0) {
        return 1;
    }
    xqc_demo_ring_queue_element_t *ele =
            (xqc_demo_ring_queue_element_t*)(ring_queue->p[ring_queue->read_idx]);
    if (ele->data_size > buf_size) {
        return -1;
    }
    memcpy(data_buf, ele->data_buf, ele->data_size);
    *out_data_size = ele->data_size;
    ele->data_size = 0;
    if (ring_queue->read_idx + 1 >= ring_queue->element_max_num) {
        ring_queue->read_idx = 0;
    } else {
        ring_queue->read_idx++;
    }
    ring_queue->element_num--;
    return 0;
}
