/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_OBJECT_MANAGER_INCLUDED_
#define _XQC_H_OBJECT_MANAGER_INCLUDED_

#include <stdint.h>
#include <assert.h>

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_list.h"

/* Generic object manager, see unit test case for usage */


typedef unsigned int xqc_object_id_t;

#define XQC_INVALID_OBJECT_ID ((xqc_object_id_t)-1)

typedef struct xqc_object_s {
    xqc_object_id_t     object_id;  /* object ID, use for object manager */
    xqc_list_head_t     list;       /* object is either in the freelist or in the usedlist */
    char                data[0];    /* other data members, variable length */
} xqc_object_t;


typedef struct xqc_object_manager_s {
    char               *object_pool;    /* object pool, pre-allocated */
    size_t              capacity;       /* object poll capacity */

    size_t              object_size;    /* size of each object */

    xqc_list_head_t     free_list;      /* free list for allocating */
    xqc_list_head_t     used_list;      /* used list, allocated */
    size_t              used_count;     /* number of objects allocated */

    xqc_allocator_t     a;              /* memory allocator */
} xqc_object_manager_t;


static inline xqc_object_manager_t *
xqc_object_manager_create(size_t object_size, size_t capacity, xqc_allocator_t a)
{
    size_t size = sizeof(xqc_object_manager_t) + (object_size * capacity);
    xqc_object_manager_t *manager = a.malloc(a.opaque, size);
    if (manager == NULL) {
        return NULL;
    }

    manager->object_pool = (char*)(manager + 1);
    manager->capacity = capacity;
    manager->object_size = object_size;

    xqc_init_list_head(&manager->free_list);
    for (size_t i = 0; i < capacity; ++i) {
        xqc_object_t *o = (xqc_object_t *)(manager->object_pool + i * object_size);
        o->object_id = i; /*设置ObjectID，且不再变化*/
        xqc_list_add_tail(&o->list, &manager->free_list);
    }

    xqc_init_list_head(&manager->used_list);

    manager->used_count = 0;
    manager->a = a;
    return manager;
}

static inline void
xqc_object_manager_destroy(xqc_object_manager_t *manager)
{
    xqc_allocator_t *a = &manager->a;
    a->free(a->opaque, manager);
}

static inline xqc_object_t *
xqc_object_manager_find(xqc_object_manager_t *manager, xqc_object_id_t id)
{
    if (id >= manager->capacity) {
        return NULL;
    }

    return (xqc_object_t *)(manager->object_pool + id * manager->object_size);
}

static inline xqc_object_t *
xqc_object_manager_alloc(xqc_object_manager_t *manager)
{
    if (manager->used_count >= manager->capacity) {
        return NULL;
    }

    assert(!xqc_list_empty(&manager->free_list));

    xqc_list_head_t* node = manager->free_list.next;
    xqc_list_del_init(node);

    xqc_list_add_tail(node, &manager->used_list);

    ++manager->used_count;

    return xqc_list_entry(node, xqc_object_t, list);
}

static inline int
xqc_object_manager_free(xqc_object_manager_t *manager, xqc_object_id_t id)
{
    xqc_object_t *o = xqc_object_manager_find(manager, id);
    if (o == NULL) {
        return -1;
    } 

    assert(!xqc_list_empty(&o->list));

    xqc_list_del_init(&o->list);
    xqc_list_add(&o->list, &manager->free_list);

    --manager->used_count;
    return 0;
}

static inline xqc_object_manager_t *
xqc_object_manager_recapacity(xqc_object_manager_t *manager, size_t new_capacity)
{
    if (manager->used_count > new_capacity) {
        return NULL;
    }

    xqc_object_manager_t *new_manager =
        xqc_object_manager_create(manager->object_size, new_capacity, manager->a);
    if (new_manager == NULL) {
        return NULL;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &manager->used_list) {
        xqc_object_t *from = xqc_list_entry(pos, xqc_object_t, list);
        xqc_object_t *to = xqc_object_manager_alloc(new_manager);
        memcpy(to->data, from->data, manager->object_size - sizeof(xqc_object_t));
    }

    xqc_object_manager_destroy(manager);

    return new_manager;
}

static inline void
xqc_object_manager_foreach(xqc_object_manager_t *manager, void (*cb)(xqc_object_t *))
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &manager->used_list)
    {
        xqc_object_t *o = xqc_list_entry(pos, xqc_object_t, list);
        cb(o);
    }
}

static inline size_t
xqc_object_manager_used_count(xqc_object_manager_t *manager)
{
    return manager->used_count;
}

static inline size_t
xqc_object_manager_free_count(xqc_object_manager_t *manager)
{
    assert(manager->capacity >= manager->used_count);
    return manager->capacity - manager->used_count;
}

#endif /*_XQC_H_OBJECT_MANAGER_INCLUDED_*/
