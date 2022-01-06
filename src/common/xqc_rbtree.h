/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_RBTREE_H_INCLUDED_
#define _XQC_RBTREE_H_INCLUDED_

#include <stdint.h>

/* Interfaces:
 * xqc_rbtree_init(), xqc_rbtree_count(), 
 * xqc_rbtree_insert(), xqc_rbtree_delete(), xqc_rbtree_delete_node(), xqc_rbtree_find()
 * xqc_rbtree_foreach()
 */

typedef enum xqc_rbtree_color_e {
    xqc_rbtree_red,
    xqc_rbtree_black,
} xqc_rbtree_color_t;

typedef uint64_t xqc_rbtree_key_t;

typedef struct xqc_rbtree_node_s {
    struct xqc_rbtree_node_s   *parent;
    struct xqc_rbtree_node_s   *left;
    struct xqc_rbtree_node_s   *right;
    xqc_rbtree_key_t            key;
    xqc_rbtree_color_t          color;
    char                        data[0];
} xqc_rbtree_node_t;

typedef struct xqc_rbtree_s {
    xqc_rbtree_node_t *root;
    size_t count;
} xqc_rbtree_t;


static inline void
xqc_rbtree_init(xqc_rbtree_t *rbtree)
{
    rbtree->root = NULL;
    rbtree->count = 0;
}

static inline size_t
xqc_rbtree_count(xqc_rbtree_t *rbtree)
{
    return rbtree->count;
}

static inline xqc_rbtree_node_t *
xqc_rbtree_find(xqc_rbtree_t *rbtree, xqc_rbtree_key_t key)
{
    xqc_rbtree_node_t *node = rbtree->root;
    while (node) {
        if (key < node->key) {
            node = node->left;

        } else if (node->key < key) {
            node = node->right;

        } else {
            return node;
        }
    }

    return NULL;
}

static inline void
xqc_rbtree_rotate_left(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *x)
{
    xqc_rbtree_node_t *y = x->right;
    x->right = y->left;
    if (y->left) {
        y->left->parent = x;
    }
    y->parent = x->parent;

    if (x->parent == NULL) {
        rbtree->root = y;

    } else if (x == x->parent->left) {
        x->parent->left = y;

    } else {
        x->parent->right = y;
    }

    y->left = x;
    x->parent = y;
}

static inline void
xqc_rbtree_rotate_right(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *y)
{
    xqc_rbtree_node_t *x = y->left;
    y->left = x->right;
    if (x->right) {
        x->right->parent = y;
    }
    x->parent = y->parent;

    if (y->parent == NULL) {
        rbtree->root = x;

    } else if (y == y->parent->right) {
        y->parent->right = x;

    } else {
        y->parent->left = x;
    }

    x->right = y;
    y->parent = x;
}

static inline void
xqc_rbtree_insert_fixup(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *x)
{
    while (x != rbtree->root && x->parent->color == xqc_rbtree_red) {
        if (x->parent == x->parent->parent->left) { /* parent is the left subtree of grand */
            /* uncle */
            xqc_rbtree_node_t* y = x->parent->parent->right; 

            if (y && y->color == xqc_rbtree_red) { /* uncle: red */
                /* case 1 */
                x->parent->color = xqc_rbtree_black;
                y->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                x = x->parent->parent;

            } else { /* uncle: black */
                if (x == x->parent->right) {
                    /* case 2 */
                    x = x->parent;
                    xqc_rbtree_rotate_left(rbtree, x);
                }

                /* case 3 */
                x->parent->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                xqc_rbtree_rotate_right(rbtree, x->parent->parent);
            }

        } else {
            /* uncle */
            xqc_rbtree_node_t* y = x->parent->parent->left; 

            if (y && y->color == xqc_rbtree_red) { /* uncle: red */
                /* case 4 */
                x->parent->color = xqc_rbtree_black;
                y->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                x = x->parent->parent;

            } else { /* uncle: black */
                if (x == x->parent->left) {
                    /* case 5 */
                    x = x->parent;
                    xqc_rbtree_rotate_right(rbtree, x);
                } 

                /* case 6 */
                x->parent->color = xqc_rbtree_black;
                x->parent->parent->color = xqc_rbtree_red;
                xqc_rbtree_rotate_left(rbtree, x->parent->parent);
            }
        }
    }

    rbtree->root->color = xqc_rbtree_black;
}

static inline int
xqc_rbtree_insert(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *node)
{
    xqc_rbtree_node_t *p = NULL;
    xqc_rbtree_node_t *x = rbtree->root;
    while (x != NULL) {
        p = x;
        if (node->key < x->key) {
            x = x->left;

        } else if (x->key < node->key) {
            x = x->right;

        } else {
            return -1; /* duplicate key */
        }
    }

    node->parent = p;
    node->left = NULL;
    node->right = NULL;
    node->color = xqc_rbtree_red;

    if (p == NULL) {
        rbtree->root = node;

    } else if (node->key < p->key) {
        p->left = node;

    } else {
        p->right = node;
    }

    xqc_rbtree_insert_fixup(rbtree, node);

    ++rbtree->count;

    return 0;
}

static inline void
xqc_rbtree_delete_fixup(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *x)
{
    while (rbtree->root != x && x->color == xqc_rbtree_black) {
        if (x == x->parent->left) {
            xqc_rbtree_node_t *w = x->parent->right;
            if (w->color == xqc_rbtree_red) {
                /* case 1 */
                w->color = xqc_rbtree_black;
                xqc_rbtree_rotate_left(rbtree, x->parent);
                w = x->parent->right;
            }

            if (w->left->color == xqc_rbtree_black && w->right->color == xqc_rbtree_black) {
                /* case 2 */
                w->color = xqc_rbtree_red;
                x = x->parent;

            } else if (w->right->color == xqc_rbtree_black) {
                /* case 3 */
                w->left->color = xqc_rbtree_black;
                w->color = xqc_rbtree_red;
                xqc_rbtree_rotate_right(rbtree, w);
                w = x->parent->right;
                w->color = x->parent->color;
                x->parent->color = xqc_rbtree_black;
                w->right->color = xqc_rbtree_black;
                xqc_rbtree_rotate_left(rbtree, x->parent);
                x = rbtree->root;
            }

        } else {
            xqc_rbtree_node_t *w = x->parent->left;
            if (w->color == xqc_rbtree_red) {
                /* case 1 */
                w->color = xqc_rbtree_black;
                xqc_rbtree_rotate_right(rbtree, x->parent);
                w = x->parent->left;
            }

            if (w->right->color == xqc_rbtree_black && w->left->color == xqc_rbtree_black) {
                /* case 2 */
                w->color = xqc_rbtree_red;
                x = x->parent;

            } else if (w->left->color == xqc_rbtree_black) {
                /* case 3 */
                w->right->color = xqc_rbtree_black;
                w->color = xqc_rbtree_red;
                xqc_rbtree_rotate_left(rbtree, w);
                w = x->parent->left;
                w->color = x->parent->color;
                x->parent->color = xqc_rbtree_black;
                w->left->color = xqc_rbtree_black;
                xqc_rbtree_rotate_right(rbtree, x->parent);
                x = rbtree->root;
            }

        }
    }

    x->color = xqc_rbtree_black;
}

static inline xqc_rbtree_node_t *
xqc_rbtree_successor(xqc_rbtree_node_t *x)
{
    if (x->right) {
        xqc_rbtree_node_t *p = x->right;
        while (p->left) {
            p = p->left;
        }
        return p;
    }

    xqc_rbtree_node_t *p = x->parent;
    xqc_rbtree_node_t *y = x;
    while (p && y == p->right) {
        y = p;
        p = p->parent;
    }

    return p;
}

static inline xqc_rbtree_node_t *
xqc_rbtree_delete_node(xqc_rbtree_t *rbtree, xqc_rbtree_node_t *z)
{
    xqc_rbtree_node_t *x = NULL;
    xqc_rbtree_node_t *y = NULL;

    if (z->left == NULL || z->right == NULL) {
        y = z;

    } else {
        y = xqc_rbtree_successor(z);
    }

    if (y->left) {
        x = y->left;

    } else {
        x = y->right;
    }

    if (x) {
        x->parent = y->parent;
    }

    if (y->parent == NULL) {
        rbtree->root = x;

    } else if (y == y->parent->left) {
        y->parent->left = x;

    } else {
        y->parent->right = x;
    }

    if (y != z) {
        z->key = y->key;
    }

    if (y->color == xqc_rbtree_black) {
        if (x) {
            xqc_rbtree_delete_fixup(rbtree, x);
        }
    }

    --rbtree->count;

    return y;
}

static inline xqc_rbtree_node_t *
xqc_rbtree_delete(xqc_rbtree_t *rbtree, xqc_rbtree_key_t key)
{
    xqc_rbtree_node_t *z = xqc_rbtree_find(rbtree, key);
    if (z == NULL) {
        return NULL;
    }
    return xqc_rbtree_delete_node(rbtree, z);
}

static inline void
xqc_rbtree_infix_order(xqc_rbtree_node_t *node, void (*callback)(xqc_rbtree_node_t *))
{
    if (node->left) {
        xqc_rbtree_infix_order(node->left, callback);
    }

    callback(node);

    if (node->right) {
        xqc_rbtree_infix_order(node->right, callback);
    }
}

static inline void
xqc_rbtree_foreach(xqc_rbtree_t *rbtree, void (*callback)(xqc_rbtree_node_t *))
{
    xqc_rbtree_node_t *root = rbtree->root;
    if (root) {
        xqc_rbtree_infix_order(root, callback);
    }
}

#endif /*_XQC_RBTREE_H_INCLUDED_*/
