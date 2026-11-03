/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/**
 * @file llist.c
 * @brief Intrusive doubly linked list used throughout libcurl.
 *
 * Nodes (struct Curl_llist_node) are embedded in the objects they link, so
 * adding an element never allocates memory. The list keeps a head, a tail
 * and a node count. Every node remembers the list it is in, which makes
 * removal possible given only the node.
 *
 * @note Not thread-safe; callers must serialize access to a list.
 * @see llist.h
 */
#include "curl_setup.h"

#include "llist.h"

/**
 * Debug-only magic values used to detect use of uninitialized, corrupted
 * or already removed lists and nodes via DEBUGASSERT().
 *
 * @internal
 */
#ifdef DEBUGBUILD
#define LLISTINIT 0x100cc001 /* random pattern */
#define NODEINIT  0x12344321 /* random pattern */
#define NODEREM   0x54321012 /* random pattern */

/**
 * @brief Debug build: validate a node pointer (NULL allowed) and return it.
 * @internal
 */
#define VERIFYNODE(x) verifynode(x)
/**
 * @brief Assert that a node pointer is NULL or an initialized node.
 * @internal
 * @param[in] n Node to check, may be NULL.
 * @return The unchanged node pointer @p n.
 * @pre If @p n is not NULL, it was linked into a list via
 *      llist_insert_next() and not removed since.
 */
static struct Curl_llist_node *verifynode(struct Curl_llist_node *n)
{
  DEBUGASSERT(!n || (n->_init == NODEINIT));
  return n;
}
#else
/**
 * @brief Release build: no verification, expands to the expression itself.
 * @internal
 */
#define VERIFYNODE(x) x
#endif
/**
 * @brief Initialize an empty list.
 *
 * Sets the list to the empty state and records the element destructor that
 * is invoked when nodes are removed with Curl_node_remove() or when the list
 * is destroyed with Curl_llist_destroy().
 *
 * @param[out] l    List to initialize; any previous contents are ignored.
 * @param[in]  dtor Destructor called for each element on removal, or NULL
 *                  if elements are not to be freed by the list.
 * @post The list is empty and ready for use.
 * @note @unittest 1300
 */
void Curl_llist_init(struct Curl_llist *l, Curl_llist_dtor dtor)
{
  l->_size = 0;
  l->_dtor = dtor;
  l->_head = NULL;
  l->_tail = NULL;
#ifdef DEBUGBUILD
  l->_init = LLISTINIT;
#endif
}

/**
 * @brief Insert a node after a given node.
 * @internal
 *
 * Inserts the new list node @p ne after the given node @p e. If @p e is
 * NULL and the list already has elements, the new node becomes the first
 * one in the list. If the list is empty, @p e is ignored.
 *
 * @param[in,out] list List to insert into; must be initialized.
 * @param[in,out] e    Node to insert after, or NULL to insert first.
 * @param[in]     p    Element pointer to store in the node.
 * @param[out]    ne   Node to link in, normally a member of the object
 *                     @p p points to. Must not be linked in any list.
 * @pre @p list and @p ne are not NULL; @p e (if given) is in @p list.
 * @post @p ne is linked and the list size grew by one.
 * @warning The node memory is owned by the caller and must stay valid for
 *          as long as it is linked.
 * @note @unittest 1300
 */
UNITTEST void llist_insert_next(struct Curl_llist *list,
                                struct Curl_llist_node *e, const void *p,
                                struct Curl_llist_node *ne);
UNITTEST void llist_insert_next(struct Curl_llist *list,
                                struct Curl_llist_node *e, /* may be NULL */
                                const void *p,
                                struct Curl_llist_node *ne)
{
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  DEBUGASSERT(ne);

#ifdef DEBUGBUILD
  ne->_init = NODEINIT;
#endif
  ne->_ptr = CURL_UNCONST(p);
  ne->_list = list;
  if(list->_size == 0) {
    list->_head = ne;
    list->_head->_prev = NULL;
    list->_head->_next = NULL;
    list->_tail = ne;
  }
  else {
    /* if 'e' is NULL here, we insert the new element first in the list */
    ne->_next = e ? e->_next : list->_head;
    ne->_prev = e;
    if(!e) {
      list->_head->_prev = ne;
      list->_head = ne;
    }
    else if(e->_next) {
      e->_next->_prev = ne;
    }
    else {
      list->_tail = ne;
    }
    if(e)
      e->_next = ne;
  }

  ++list->_size;
}

/**
 * @brief Add a node to the end of the list.
 *
 * @param[in,out] list List to append to; must be initialized.
 * @param[in]     p    Element pointer to store in the node.
 * @param[out]    ne   Node to link in, normally embedded in the object that
 *                     @p p points to. Must not already be in a list.
 * @post @p ne is the tail of the list.
 * @warning The list does not copy the node: keep it alive while linked.
 * @see llist_insert_next()
 * @note @unittest 1300
 */
void Curl_llist_append(struct Curl_llist *list, const void *p,
                       struct Curl_llist_node *ne)
{
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  DEBUGASSERT(ne);
  llist_insert_next(list, list->_tail, p, ne);
}

/**
 * @brief Unlink a node from its list and hand back its element.
 *
 * Removes @p e from the list it belongs to and clears the node. The list's
 * destructor is NOT called, ownership of the element passes to the caller.
 *
 * @param[in,out] e Node to unlink, may be NULL.
 * @return The element pointer that was stored in the node, or NULL when
 *         @p e is NULL.
 * @post The node is not in any list (debug builds mark it as removed).
 * @warning Using a node after removal in a debug build trips assertions.
 * @see Curl_node_remove()
 */
void *Curl_node_take_elem(struct Curl_llist_node *e)
{
  void *ptr;
  struct Curl_llist *list;
  if(!e)
    return NULL;

  list = e->_list;
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  DEBUGASSERT(list->_size);
  DEBUGASSERT(e->_init == NODEINIT);
  if(list) {
    if(e == list->_head) {
      list->_head = e->_next;

      if(!list->_head)
        list->_tail = NULL;
      else
        e->_next->_prev = NULL;
    }
    else {
      if(e->_prev)
        e->_prev->_next = e->_next;

      if(!e->_next)
        list->_tail = e->_prev;
      else
        e->_next->_prev = e->_prev;
    }
    --list->_size;
  }
  ptr = e->_ptr;

  e->_list = NULL;
  e->_ptr  = NULL;
  e->_prev = NULL;
  e->_next = NULL;
#ifdef DEBUGBUILD
  e->_init = NODEREM; /* specific pattern on remove - not zero */
#endif

  return ptr;
}

/**
 * @brief Remove a node and run the list destructor on its element.
 * @internal
 * @param[in,out] e    Node to remove, may be NULL (then nothing happens).
 * @param[in]     user Opaque pointer passed to the list's destructor.
 * @note The destructor is only invoked if the list has one.
 */
static void node_uremove(struct Curl_llist_node *e, void *user)
{
  struct Curl_llist *list;
  void *ptr;
  if(!e)
    return;

  list = e->_list;
  DEBUGASSERT(list);
  if(list) {
    ptr = Curl_node_take_elem(e);
    if(list->_dtor)
      list->_dtor(user, ptr);
  }
}

/**
 * @brief Remove a node from its list and destroy its element.
 *
 * Like Curl_node_take_elem(), but also calls the list's destructor on the
 * element (with a NULL user pointer).
 *
 * @param[in,out] e Node to remove, may be NULL.
 * @warning After the call the element may have been freed by the destructor.
 */
void Curl_node_remove(struct Curl_llist_node *e)
{
  node_uremove(e, NULL);
}

/**
 * @brief Remove all nodes of a list, running the destructor on each.
 *
 * Nodes are removed starting at the tail. The list struct itself is not
 * freed; it stays empty and may be reused.
 *
 * @param[in,out] list List to empty, may be NULL.
 * @param[in]     user Opaque pointer passed to the destructor for each
 *                     element.
 */
void Curl_llist_destroy(struct Curl_llist *list, void *user)
{
  if(list) {
    DEBUGASSERT(list->_init == LLISTINIT);
    while(list->_size > 0)
      node_uremove(list->_tail, user);
  }
}

/**
 * @brief Get the first node of a list.
 * @param[in] list Initialized list.
 * @return The first node, or NULL if the list is empty.
 */
struct Curl_llist_node *Curl_llist_head(const struct Curl_llist *list)
{
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  return VERIFYNODE(list->_head);
}

#ifdef UNITTESTS
/**
 * @brief Get the last node of a list (unit tests only).
 * @internal
 * @param[in] list Initialized list.
 * @return The last node, or NULL if the list is empty.
 * @note @unittest 1300
 */
UNITTEST struct Curl_llist_node *llist_tail(const struct Curl_llist *list);
UNITTEST struct Curl_llist_node *llist_tail(const struct Curl_llist *list)
{
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  return VERIFYNODE(list->_tail);
}
#endif

/**
 * @brief Get the number of nodes in a list.
 * @param[in] list Initialized list.
 * @return Number of nodes currently linked in @p list.
 */
size_t Curl_llist_count(const struct Curl_llist *list)
{
  DEBUGASSERT(list);
  DEBUGASSERT(list->_init == LLISTINIT);
  return list->_size;
}

/**
 * @brief Get the element stored in a node.
 * @param[in] n Node, must not be NULL and must be linked.
 * @return The custom data pointer given when the node was inserted.
 */
void *Curl_node_elem(const struct Curl_llist_node *n)
{
  DEBUGASSERT(n);
  DEBUGASSERT(n->_init == NODEINIT);
  return n->_ptr;
}

/**
 * @brief Get the node following a given node.
 * @param[in] n Node, must not be NULL.
 * @return The next node, or NULL if @p n is the last one.
 */
struct Curl_llist_node *Curl_node_next(const struct Curl_llist_node *n)
{
  DEBUGASSERT(n);
  DEBUGASSERT(n->_init == NODEINIT);
  return VERIFYNODE(n->_next);
}

#ifdef UNITTESTS
/**
 * @brief Get the node preceding a given node (unit tests only).
 * @internal
 * @param[in] n Node, must not be NULL.
 * @return The previous node, or NULL if @p n is the first one.
 * @note @unittest 1300
 */
UNITTEST struct Curl_llist_node *llist_node_prev(
  const struct Curl_llist_node *n);
UNITTEST struct Curl_llist_node *llist_node_prev(
  const struct Curl_llist_node *n)
{
  DEBUGASSERT(n);
  DEBUGASSERT(n->_init == NODEINIT);
  return VERIFYNODE(n->_prev);
}
#endif

/**
 * @brief Get the list a node belongs to.
 * @param[in] n Node, must not be NULL.
 * @return The owning list, or NULL if the node is not linked in a list.
 */
struct Curl_llist *Curl_node_llist(const struct Curl_llist_node *n)
{
  DEBUGASSERT(n);
  DEBUGASSERT(!n->_list || n->_init == NODEINIT);
  return n->_list;
}
