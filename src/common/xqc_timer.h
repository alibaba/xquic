/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_TIMER_INCLUDE_
#define _XQC_H_TIMER_INCLUDE_

#include <stdint.h>
#include "src/common/xqc_time.h"
#include "src/common/xqc_list.h"

/* Timing-Wheel based timer with an accuracy of 1 millisecond
 * 
 * Interfaces:
 * xqc_timer_manager_init()
 * xqc_timer_manager_tick()
 * xqc_timer_manager_add()
 */

/* timer callback function */
typedef void (*xqc_timer_function)(unsigned long);

typedef struct xqc_timer_s {
    xqc_list_head_t     list;
    unsigned long       expires;    /* expiry time */
    unsigned long       data;       /* data passed to the callback function */
    xqc_timer_function  function;   /* callback function */
} xqc_timer_t;


static inline void
xqc_timer_init(xqc_timer_t *timer)
{
    timer->list.prev = NULL;
    timer->list.next = NULL;
    timer->expires = 0;
    timer->data = 0;
    timer->function = NULL;
}

#define XQC_VEC1_BITS (14)
#define XQC_VEC2_BITS (8)

#define XQC_VEC1_SIZE (1 << (XQC_VEC1_BITS))
#define XQC_VEC2_SIZE (1 << (XQC_VEC2_BITS))

#define XQC_VEC1_MASK ((XQC_VEC1_SIZE) - 1)
#define XQC_VEC2_MASK ((XQC_VEC2_SIZE) - 1)

/* timer manager, globally unique */
typedef struct xqc_timer_manager_s {
    uint64_t        timestamp;              /* last tick timestamp */   /* TODO: use typedef */

    unsigned int    index1;                 /* index of vec1 */
    xqc_list_head_t vec1[XQC_VEC1_SIZE];    /* urgency timer */

    unsigned int    index2;                 /* index of vec2 */
    xqc_list_head_t vec2[XQC_VEC2_SIZE];    /* loose timer */
} xqc_timer_manager_t;

static inline uint64_t
xqc_gettimeofday()
{
    /* get microsecond unit time */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return  ul;
}


static inline void
xqc_timer_manager_init(xqc_timer_manager_t *manager)
{
    manager->timestamp = xqc_gettimeofday();

    manager->index1 = manager->timestamp & XQC_VEC1_MASK;
    for (int i = 0; i < XQC_VEC1_SIZE; ++i) {
        xqc_init_list_head(&manager->vec1[i]);
    }

    manager->index2 = (manager->timestamp >> XQC_VEC1_BITS) & XQC_VEC2_MASK;
    for (int i = 0; i < XQC_VEC2_SIZE; ++i) {
        xqc_init_list_head(&manager->vec2[i]);
    }
}

static inline int
xqc_timer_manager_internal_add(xqc_timer_manager_t *manager, xqc_timer_t *timer)
{
    xqc_list_head_t *vec = NULL;

    unsigned long expires= timer->expires;
    unsigned long idx = expires - manager->timestamp;

    if (idx < XQC_VEC1_SIZE) {
        int i = expires & XQC_VEC1_MASK;
        vec = manager->vec1 + i;

    } else if (idx < (1 << (XQC_VEC1_BITS + XQC_VEC2_BITS))) {
        int i = (expires >> XQC_VEC1_BITS) & XQC_VEC2_MASK;
        vec = manager->vec2 + i;

    } else {
        printf("xqc timer add error:%lu\n", idx);
        return -1;
    }

    xqc_list_add(&timer->list, vec->prev);
    return 0;
}


static inline int
xqc_timer_manager_add(xqc_timer_manager_t *manager, xqc_timer_t *timer, unsigned long timeout)
{
    if (timer->function == NULL) {
        printf("timer function null\n");
        return 1;
    }
    unsigned long now = xqc_gettimeofday();
    timer->expires = now + timeout;
    int ret = xqc_timer_manager_internal_add(manager, timer);
#if 0
    if (ret == 0) {
        printf("add timer OK, timeout=%lu, expires=%lu\n", timeout, timer->expires);
    }
#endif
    return ret;
}

static inline void
xqc_timer_manager_cascade(xqc_timer_manager_t *manager)
{
    xqc_list_head_t *head, *curr, *next;

    head = manager->vec2 + manager->index2;
    curr = head->next;
    while (curr != head) {
        xqc_timer_t *tmp = xqc_list_entry(curr, xqc_timer_t, list);
        next = curr->next;

        xqc_list_del(curr);
        curr->next = curr->prev = NULL;

        xqc_timer_manager_internal_add(manager, tmp);

        curr = next;
    }

    head->prev = head->next = head;
    manager->index2 = (manager->index2 + 1) & XQC_VEC2_MASK;
}


static inline void
xqc_timer_manager_tick(xqc_timer_manager_t *manager)
{
    unsigned long now = xqc_gettimeofday();
    while (now >= manager->timestamp) {
        if (manager->index1 == 0) {
            xqc_timer_manager_cascade(manager);
        }

        xqc_list_head_t *head = manager->vec1 + manager->index1;
        xqc_list_head_t *curr = head->next;

        while (curr != head) {
            xqc_timer_t *timer = xqc_list_entry(curr, xqc_timer_t, list);
            xqc_timer_function fn = timer->function;
            unsigned long data= timer->data;

            xqc_list_del(&timer->list);
            timer->list.prev = timer->list.next = NULL;

            fn(data);

            head = manager->vec1 + manager->index1;
            curr = head->next;
        }

        manager->timestamp++;
        manager->index1 = (manager->index1 + 1) & XQC_VEC1_MASK;
    }
}

#endif /*_XQC_H_TIMER_INCLUDE_*/

