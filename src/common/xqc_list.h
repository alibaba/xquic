/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_LIST_INCLUDE_
#define _XQC_H_LIST_INCLUDE_


#include <stddef.h>
#include <assert.h>
#include "xqc_common.h"

#define XQC_LIST_POISON1  ((void *) 0x1)
#define XQC_LIST_POISON2  ((void *) 0x2)

/* the structure can be chained with a linked list by embedding xqc_list_head_t
 *
 * Interfaces:
 * xqc_list_head_init(), xqc_init_list_head()
 * xqc_list_add(), xqc_list_add_tail()
 * xqc_list_del(), xqc_list_del_init()
 * xqc_list_replace()
 * xqc_list_empty()
 * xqc_list_for_each(), xqc_list_for_each_safe()
 * xqc_list_entry()
 */

typedef struct xqc_list_head_s {
    struct xqc_list_head_s *prev;
    struct xqc_list_head_s *next;
} xqc_list_head_t;

#define xqc_list_head_init(name) { &(name), &(name) }

#if GNU11
# define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#else
#define container_of(ptr, type, member) (type *)( (char *)ptr - offsetof(type, member) )
#endif

#define xqc_list_entry(ptr, type, member) container_of(ptr, type, member)

static inline void
xqc_init_list_head(xqc_list_head_t *list)
{
    list->prev = list;
    list->next = list;
}

static inline void
__xqc_list_add(xqc_list_head_t *node, xqc_list_head_t *prev, xqc_list_head_t *next)
{
#if (XQC_DEBUG)
    assert(next->prev == prev && prev->next == next && node != prev && node != next);
#endif

    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

static inline void
xqc_list_add(xqc_list_head_t *node, xqc_list_head_t *head)
{
    __xqc_list_add(node, head, head->next);
}

static inline void
xqc_list_add_tail(xqc_list_head_t *node, xqc_list_head_t *head)
{
    __xqc_list_add(node, head->prev, head);
}

static inline void
__xqc_list_del(xqc_list_head_t *prev, xqc_list_head_t *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void
__xqc_list_del_entry(xqc_list_head_t *entry)
{
#if (XQC_DEBUG)
    xqc_list_head_t *prev, *next;

    prev = entry->prev;
    next = entry->next;

    assert(prev != NULL && next != NULL);
    assert(next != XQC_LIST_POISON1 
           && prev != XQC_LIST_POISON2
           && prev->next == entry 
           && next->prev == entry);
#endif

    __xqc_list_del(entry->prev, entry->next);
}

static inline void
xqc_list_del(xqc_list_head_t *entry)
{
    __xqc_list_del_entry(entry);
    entry->next = XQC_LIST_POISON1;
    entry->prev = XQC_LIST_POISON2;
}

static inline void
xqc_list_del_init(xqc_list_head_t *entry)
{
    __xqc_list_del_entry(entry);
    xqc_init_list_head(entry);
}

static inline void
xqc_list_replace(xqc_list_head_t *old, xqc_list_head_t *node)
{
    node->next = old->next;
    node->next->prev = node;
    node->prev = old->prev;
    node->prev->next = node;
}

static inline int
xqc_list_empty(const xqc_list_head_t *head)
{
    return head->next == head;
}

#define xqc_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define xqc_list_for_each_from(pos, head) \
    for (; pos != (head); pos = pos->next)

#define xqc_list_for_each_reverse(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define xqc_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; \
        pos != (head); \
        pos = n, n = pos->next)

#endif /*_XQC_H_LIST_INCLUDE_*/
