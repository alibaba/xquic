/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_QUEUE_H_INCLUDE_
#define _XQC_QUEUE_H_INCLUDE_

#include <stddef.h>

/* Queue implement using doubly linked-list */

typedef struct xqc_queue_s {
    struct xqc_queue_s *prev;
    struct xqc_queue_s *next;
} xqc_queue_t;

#define xqc_queue_initialize(q) { &(q), &(q) }

#define xqc_queue_init(q) \
    do\
    {\
        (q)->prev = q;\
        (q)->next = q;\
    } while (0)

#define xqc_queue_empty(q)\
    ((q) == (q)->prev)

#define xqc_queue_insert_head(h, x)\
    do\
    {\
        (x)->next = (h)->next;\
        (x)->next->prev = x;\
        (x)->prev = h;\
        (h)->next = x;\
    } while (0)

#define xqc_queue_insert_tail(h, x)\
    do\
    {\
        (x)->prev = (h)->prev;\
        (x)->prev->next = x;\
        (x)->next = h;\
        (h)->prev = x;\
    } while (0)

#define xqc_queue_head(q) (q)->next

#define xqc_queue_tail(q) (q)->prev

#define xqc_queue_prev(q) (q)->prev

#define xqc_queue_next(q) (q)->next

#define xqc_queue_remove(x)\
    do\
    {\
        (x)->next->prev = (x)->prev;\
        (x)->prev->next = (x)->next;\
        (x)->prev = NULL;\
        (x)->next = NULL;\
    } while (0)

#define xqc_queue_data(q, type, member)\
    ((type *)((char *)(q) - offsetof(type, member)))

#define xqc_queue_foreach(pos, q)\
    for (pos = (q)->next; pos != (q); pos = pos->next)

#endif /*_XQC_QUEUE_H_INCLUDE_*/
