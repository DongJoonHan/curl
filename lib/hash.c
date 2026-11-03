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
 * @file hash.c
 * @brief Chained hash table with byte-string and socket keys.
 *
 * Implements struct Curl_hash: a fixed-slot-count hash table whose buckets
 * are singly linked lists of struct Curl_hash_element. Keys are copied into
 * the element, values are stored as pointers and released through a
 * destructor. Two key types are supported: arbitrary byte strings and
 * curl_socket_t values. The table array is allocated lazily on first add.
 *
 * @note Not thread-safe; callers must serialize access.
 * @warning The byte-string hash is seeded randomly at global init
 *          (Curl_hash_global_init()) to resist hash flooding.
 * @see hash.h
 */
#include "curl_setup.h"

#include <stddef.h> /* for offsetof() */

#include "hash.h"
#include "rand.h"

/* random patterns for API verification */
/**
 * @brief Debug-only magic patterns for API verification.
 *
 * HASHINIT marks an initialized struct Curl_hash, ITERINIT marks an
 * initialized iterator. They catch use of uninitialized objects.
 * @internal
 */
#ifdef DEBUGBUILD
#define HASHINIT 0x7017e781
#define ITERINIT 0x5FEDCBA9
#endif


/**
 * @brief Function computing the slot index for a key.
 * @internal
 * @param[in] key        Key bytes.
 * @param[in] key_length Length of the key in bytes.
 * @param[in] slots_num  Number of slots in the table (must be non-zero).
 * @return Slot index in the range [0, slots_num).
 */
typedef size_t (*hash_function)(const void *key,
                                size_t key_length,
                                size_t slots_num);

/**
 * @brief Function comparing two keys for equality.
 * @internal
 * @param[in] key1     First key.
 * @param[in] key1_len Length of the first key.
 * @param[in] key2     Second key.
 * @param[in] key2_len Length of the second key.
 * @return Non-zero if the keys are equal, 0 otherwise.
 */
typedef size_t (*comp_function)(const void *key1,
                                size_t key1_len,
                                const void *key2,
                                size_t key2_len);

/* Curl_hash stores its type in a uint8_t. */
/**
 * @brief Compile-time check that all hash types fit the uint8_t type field.
 *
 * Curl_hash stores its type in a uint8_t. The array size becomes -1 (a
 * compile error) if CURL_HASH_TYPE_LAST grows beyond that.
 * @internal
 */
typedef char hash_types_fit_uint8[
  ((CURL_HASH_TYPE_LAST - 1) <= UINT8_MAX) ? 1 : -1];

/**
 * @brief Pair of functions implementing one hash key type.
 * @internal
 */
struct hash_functions {
  /** @brief Computes the slot for a key. */
  hash_function hash;
  /** @brief Compares two keys for equality. */
  comp_function compare;
};

/* set at global init, read-only afterwards */
/**
 * @brief Random seed mixed into the string hash.
 *
 * Set once by Curl_hash_global_init() and read-only afterwards, so no
 * locking is needed for reads.
 * @internal
 */
static size_t hash_seed;

/**
 * @brief Initialize the global hash seed.
 *
 * Draws random bytes to seed the string hash function. Calling it again
 * after success is a cheap no-op. A seed of 0 is replaced by 1.
 *
 * @return CURLE_OK on success (or if already seeded), otherwise the error
 *         from Curl_rand_bytes().
 * @post On CURLE_OK the global seed is set and must not change again.
 * @warning Not thread-safe: call during global initialization only.
 */
CURLcode Curl_hash_global_init(void)
{
  static bool seeded;
  unsigned char buf[sizeof(size_t)];
  size_t seed = 0;
  size_t i;
  CURLcode result;

  if(seeded)
    return CURLE_OK;

  result = Curl_rand_bytes(NULL,
#ifdef DEBUGBUILD
                           FALSE,
#endif
                           buf, sizeof(buf));
  if(result)
    return result;

  for(i = 0; i < sizeof(buf); i++)
    seed = (seed << 8) | buf[i];

  hash_seed = seed ? seed : 1;
  seeded = TRUE;
  return CURLE_OK;
}

/**
 * @brief Seeded string hash (djb2 variant: h = h * 33 ^ c).
 * @internal
 * @param[in] key        Key bytes.
 * @param[in] key_length Number of bytes in the key.
 * @param[in] slots_num  Number of slots, must be non-zero.
 * @param[in] seed       Value XORed into the initial hash state.
 * @return Slot index in [0, slots_num).
 * @note @unittest 1603
 */
UNITTEST size_t hash_str_seeded(const void *key, size_t key_length,
                                size_t slots_num, size_t seed);
UNITTEST size_t hash_str_seeded(const void *key, size_t key_length,
                                size_t slots_num, size_t seed)
{
  const char *key_str = (const char *)key;
  const char *end = key_str + key_length;
  size_t h = 5381 ^ seed;

  while(key_str < end) {
    size_t j = (size_t)*key_str++;
    h += h << 5;
    h ^= j;
  }

  return (h % slots_num);
}

/**
 * @brief String hash using the global seed.
 * @internal
 * @param[in] key        Key bytes.
 * @param[in] key_length Number of bytes in the key.
 * @param[in] slots_num  Number of slots, must be non-zero.
 * @return Slot index in [0, slots_num).
 * @see hash_str_seeded()
 * @note @unittest 1603
 */
UNITTEST size_t hash_str(const void *key, size_t key_length, size_t slots_num);
UNITTEST size_t hash_str(const void *key, size_t key_length, size_t slots_num)
{
  return hash_str_seeded(key, key_length, slots_num, hash_seed);
}

/* Avoid treating the variable-length key[1] as a one-byte object. */
/**
 * @brief Get a pointer to the key bytes stored in an element.
 * @internal
 *
 * Avoids treating the variable-length key[1] member as a one-byte object.
 *
 * @param[in] he Hash element.
 * @return Pointer to the key storage that follows the element header.
 */
static char *hash_elem_key(struct Curl_hash_element *he)
{
  return (char *)he + offsetof(struct Curl_hash_element, key);
}

/**
 * @brief Slot function for curl_socket_t keys.
 * @internal
 * @param[in] key        Pointer to a curl_socket_t value.
 * @param[in] key_length Must equal sizeof(curl_socket_t).
 * @param[in] slots_num  Number of slots, must be non-zero.
 * @return Slot index, or 0 if the key length is wrong.
 */
static size_t hash_socket(const void *key, size_t key_length,
                          size_t slots_num)
{
  curl_socket_t socket;

  DEBUGASSERT(key_length == sizeof(socket));
  if(key_length != sizeof(socket))
    return 0;
  memcpy(&socket, key, sizeof(socket));
  return (size_t)(socket % (curl_socket_t)slots_num);
}

/**
 * @brief Compare two curl_socket_t keys.
 * @internal
 * @param[in] key1     Pointer to the first socket value.
 * @param[in] key1_len Length of the first key.
 * @param[in] key2     Pointer to the second socket value.
 * @param[in] key2_len Length of the second key.
 * @return 1 if both lengths are sizeof(curl_socket_t) and the values are
 *         equal, 0 otherwise.
 */
static size_t compare_socket(const void *key1, size_t key1_len,
                             const void *key2, size_t key2_len)
{
  curl_socket_t socket1;
  curl_socket_t socket2;

  if((key1_len != sizeof(socket1)) || (key2_len != sizeof(socket2)))
    return 0;
  memcpy(&socket1, key1, sizeof(socket1));
  memcpy(&socket2, key2, sizeof(socket2));
  return socket1 == socket2;
}

/**
 * @brief Compare two byte-string keys.
 * @internal
 * @param[in] key1     First key.
 * @param[in] key1_len Length of the first key.
 * @param[in] key2     Second key.
 * @param[in] key2_len Length of the second key.
 * @return Non-zero if lengths and contents are identical, 0 otherwise.
 */
static size_t compare_bytes(const void *key1, size_t key1_len,
                            const void *key2, size_t key2_len)
{
  return (key1_len == key2_len) && !memcmp(key1, key2, key1_len);
}

/**
 * @brief Function table indexed by hash type (CURL_HASH_TYPE_*).
 * @internal
 */
static const struct hash_functions hash_functions[] = {
  { hash_str, compare_bytes },
  { hash_socket, compare_socket }
};

/**
 * @brief Look up the hash and compare functions for a hash type.
 * @internal
 * @param[in] type A CURL_HASH_TYPE_* value.
 * @return The matching function pair; unknown types fall back to the
 *         byte-string implementation.
 */
static const struct hash_functions *hash_get_functions(uint8_t type)
{
  DEBUGASSERT(CURL_ARRAYSIZE(hash_functions) == CURL_HASH_TYPE_LAST);
  if((unsigned int)type >= CURL_HASH_TYPE_LAST)
    type = CURL_HASH_TYPE_BYTES;
  return &hash_functions[type];
}

/**
 * @brief Check that a key length is acceptable for a hash type.
 * @internal
 * @param[in] type    A CURL_HASH_TYPE_* value.
 * @param[in] key_len Key length in bytes.
 * @return TRUE for any length with CURL_HASH_TYPE_BYTES; for
 *         CURL_HASH_TYPE_SOCKET only if @p key_len is sizeof(curl_socket_t).
 *         FALSE otherwise.
 */
static bool hash_key_is_valid(uint8_t type, size_t key_len)
{
  return (type == CURL_HASH_TYPE_BYTES) ||
    ((type == CURL_HASH_TYPE_SOCKET) &&
     (key_len == sizeof(curl_socket_t)));
}

/**
 * Debugging helpers, disabled by default: iterate over all elements and dump
 * the hash contents to stderr. Enable by changing the preprocessor guard.
 */
#if 0 /* useful function for debugging hashes and their contents */
static struct Curl_hash_element *hash_next_element(
  struct Curl_hash_iterator *iter)
{
  struct Curl_hash *h;
  DEBUGASSERT(iter->init == ITERINIT);
  h = iter->hash;
  if(!h->table)
    return NULL; /* empty hash, nothing to return */

  /* Get the next element in the current list, if any */
  if(iter->current)
    iter->current = iter->current->next;

  /* If we have reached the end of the list, find the next one */
  if(!iter->current) {
    size_t i;
    for(i = iter->slot_index; i < h->slots; i++) {
      if(h->table[i]) {
        iter->current = h->table[i];
        iter->slot_index = i + 1;
        break;
      }
    }
  }

  return iter->current;
}

static void hash_start_iterate(struct Curl_hash *hash,
                               struct Curl_hash_iterator *iter)
{
  DEBUGASSERT(hash->init == HASHINIT);
  iter->hash = hash;
  iter->slot_index = 0;
  iter->current = NULL;
#ifdef DEBUGBUILD
  iter->init = ITERINIT;
#endif
}

void Curl_hash_print(struct Curl_hash *h, void (*func)(void *))
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;
  size_t last_index = UINT_MAX;

  if(!h)
    return;

  curl_mfprintf(stderr, "=Hash dump=\n");

  hash_start_iterate(h, &iter);

  he = hash_next_element(&iter);
  while(he) {
    if(iter.slot_index != last_index) {
      curl_mfprintf(stderr, "index %d:", (int)iter.slot_index);
      if(last_index != UINT_MAX) {
        curl_mfprintf(stderr, "\n");
      }
      last_index = iter.slot_index;
    }

    if(func)
      func(he->ptr);
    else
      curl_mfprintf(stderr, " [key=%.*s, he=%p, ptr=%p]",
                    (int)he->key_len, hash_elem_key(he),
                    (void *)he, (void *)he->ptr);

    he = hash_next_element(&iter);
  }
  curl_mfprintf(stderr, "\n");
}
#endif

/**
 * @brief Initialize a hash structure.
 *
 * Prepares an empty hash. The slot table is allocated lazily on the first
 * insert, so this function cannot fail.
 *
 * @param[out] h     Hash to initialize.
 * @param[in]  slots Number of slots (buckets), must be non-zero.
 * @param[in]  type  Key type, one of the CURL_HASH_TYPE_* values.
 * @param[in]  dtor  Default destructor for stored values; must not be NULL.
 * @post The hash is empty and usable; release it with Curl_hash_destroy().
 * @note @unittest 1602, 1603
 */
void Curl_hash_init(struct Curl_hash *h,
                    size_t slots,
                    Curl_hash_type type,
                    Curl_hash_dtor dtor)
{
  DEBUGASSERT(h);
  DEBUGASSERT(slots);
  DEBUGASSERT((unsigned int)type < CURL_HASH_TYPE_LAST);
  DEBUGASSERT(dtor);

  h->table = NULL;
  h->dtor = dtor;
  h->size = 0;
  h->slots = slots;
  h->type = (uint8_t)type;
#ifdef DEBUGBUILD
  h->init = HASHINIT;
#endif
}

/**
 * @brief Allocate a new element and copy the key into it.
 * @internal
 * @param[in] key     Key bytes to copy.
 * @param[in] key_len Key length in bytes.
 * @param[in] p       Value pointer to store.
 * @param[in] dtor    Per-element destructor, or NULL to use the default.
 * @return The new element, or NULL on out of memory.
 * @note The key is stored in the same allocation, after the header.
 */
static struct Curl_hash_element *hash_elem_create(const void *key,
                                                  size_t key_len,
                                                  void *p,
                                                  Curl_hash_elem_dtor dtor)
{
  struct Curl_hash_element *he;

  /* allocate the struct plus memory after it to store the key */
  he = curlx_malloc(sizeof(struct Curl_hash_element) + key_len);
  if(he) {
    he->next = NULL;
    /* copy the key */
    memcpy(hash_elem_key(he), key, key_len);
    he->key_len = key_len;
    he->ptr = p;
    he->dtor = dtor;
  }
  return he;
}

/**
 * @brief Release the value of an element, keeping the element itself.
 * @internal
 *
 * Calls the element destructor if set, otherwise the hash-wide default
 * destructor, then sets the value pointer to NULL. Does nothing if the
 * value is already NULL.
 *
 * @param[in]     h  Owning hash.
 * @param[in,out] he Element whose value is released.
 */
static void hash_elem_clear_ptr(struct Curl_hash *h,
                                struct Curl_hash_element *he)
{
  DEBUGASSERT(h);
  DEBUGASSERT(he);
  if(he->ptr) {
    if(he->dtor)
      he->dtor(hash_elem_key(he), he->key_len, he->ptr);
    else
      h->dtor(he->ptr);
    he->ptr = NULL;
  }
}

/**
 * @brief Release the value of an element and free the element.
 * @internal
 * @param[in]     h  Owning hash.
 * @param[in,out] he Element to free; invalid after the call.
 * @pre @p he was already unlinked from its slot chain.
 */
static void hash_elem_destroy(struct Curl_hash *h,
                              struct Curl_hash_element *he)
{
  hash_elem_clear_ptr(h, he);
  curlx_free(he);
}

/**
 * @brief Remove an element from its slot chain and update the count.
 * @internal
 * @param[in,out] h         Owning hash.
 * @param[in,out] he_anchor Pointer to the link that points to @p he.
 * @param[in]     he        Element to unlink.
 * @note The element is not freed.
 */
static void hash_elem_unlink(struct Curl_hash *h,
                             struct Curl_hash_element **he_anchor,
                             struct Curl_hash_element *he)
{
  *he_anchor = he->next;
  --h->size;
}

/**
 * @brief Insert an element at the head of a slot chain.
 * @internal
 * @param[in,out] h         Owning hash.
 * @param[in,out] he_anchor Slot head pointer to insert at.
 * @param[in,out] he        Element to link in.
 */
static void hash_elem_link(struct Curl_hash *h,
                           struct Curl_hash_element **he_anchor,
                           struct Curl_hash_element *he)
{
  he->next = *he_anchor;
  *he_anchor = he;
  ++h->size;
}

/**
 * @brief Insert a value into the hash with a per-element destructor.
 *
 * If the key already exists, the old value is released (with its own
 * destructor) and replaced. The slot table is allocated on first use.
 *
 * @param[in,out] h       Initialized hash.
 * @param[in]     key     Key bytes; they are copied.
 * @param[in]     key_len Key length in bytes; must be
 *                        sizeof(curl_socket_t) for socket hashes.
 * @param[in]     p       Value pointer to store.
 * @param[in]     dtor    Destructor for this value, or NULL to use the
 *                        default destructor of the hash.
 * @return @p p on success, NULL on invalid key length or out of memory.
 * @retval NULL Failure: the hash is unchanged and @p p is NOT freed.
 * @warning On success the hash owns @p p and will destroy it.
 * @see Curl_hash_add()
 */
void *Curl_hash_add2(struct Curl_hash *h,
                     const void *key, size_t key_len, void *p,
                     Curl_hash_elem_dtor dtor)
{
  const struct hash_functions *functions;
  struct Curl_hash_element *he, **slot;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == HASHINIT);
  if(!hash_key_is_valid(h->type, key_len))
    return NULL;
  if(!h->table) {
    h->table = curlx_calloc(h->slots, sizeof(struct Curl_hash_element *));
    if(!h->table)
      return NULL; /* OOM */
  }

  functions = hash_get_functions(h->type);
  slot = &h->table[functions->hash(key, key_len, h->slots)];
  for(he = *slot; he; he = he->next) {
    if(functions->compare(hash_elem_key(he), he->key_len, key, key_len)) {
      /* existing key entry, overwrite by clearing old pointer */
      hash_elem_clear_ptr(h, he);
      he->ptr = p;
      he->dtor = dtor;
      return p;
    }
  }

  he = hash_elem_create(key, key_len, p, dtor);
  if(!he)
    return NULL; /* OOM */

  hash_elem_link(h, slot, he);
  return p; /* return the new entry */
}

/**
 * @brief Insert a value into the hash using the default destructor.
 *
 * If there already was a match in the hash, that data is replaced. The
 * table is allocated "lazily" if needed, it is not done in
 * Curl_hash_init().
 *
 * @param[in,out] h       Initialized hash.
 * @param[in]     key     Key bytes; they are copied.
 * @param[in]     key_len Key length in bytes.
 * @param[in]     p       Value pointer to store.
 * @return @p p on success, NULL on failure (caller keeps ownership).
 * @see Curl_hash_add2()
 * @note @unittest 1305, 1602, 1603
 */
void *Curl_hash_add(struct Curl_hash *h,
                    const void *key, size_t key_len, void *p)
{
  return Curl_hash_add2(h, key, key_len, p, NULL);
}

/**
 * @brief Remove the identified hash entry and destroy its value.
 *
 * @param[in,out] h       Initialized hash.
 * @param[in]     key     Key bytes to look up.
 * @param[in]     key_len Key length in bytes.
 * @return 0 if an entry was removed, non-zero (1) if the key was not
 *         found or the key length is invalid.
 * @note @unittest 1603
 */
int Curl_hash_delete(struct Curl_hash *h, const void *key, size_t key_len)
{
  const struct hash_functions *functions;

  DEBUGASSERT(h);
  DEBUGASSERT(h->slots);
  DEBUGASSERT(h->init == HASHINIT);
  if(!hash_key_is_valid(h->type, key_len))
    return 1;
  if(h->table) {
    struct Curl_hash_element *he, **he_anchor;

    functions = hash_get_functions(h->type);
    he_anchor = &h->table[functions->hash(key, key_len, h->slots)];
    while(*he_anchor) {
      he = *he_anchor;
      if(functions->compare(hash_elem_key(he), he->key_len, key, key_len)) {
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
        return 0;
      }
      he_anchor = &he->next;
    }
  }
  return 1;
}

/**
 * @brief Retrieve the value stored for a key.
 *
 * @param[in] h       Initialized hash.
 * @param[in] key     Key bytes to look up.
 * @param[in] key_len Key length in bytes.
 * @return The stored value pointer, or NULL if not found, the key length
 *         is invalid, or the stored value is NULL.
 * @warning The hash keeps ownership of the returned pointer; it becomes
 *          invalid when the entry is deleted or replaced.
 * @note @unittest 1603
 */
void *Curl_hash_pick(struct Curl_hash *h, const void *key, size_t key_len)
{
  const struct hash_functions *functions;

  DEBUGASSERT(h);
  DEBUGASSERT(h->init == HASHINIT);
  if(!hash_key_is_valid(h->type, key_len))
    return NULL;
  if(h->table) {
    struct Curl_hash_element *he;
    DEBUGASSERT(h->slots);
    functions = hash_get_functions(h->type);
    he = h->table[functions->hash(key, key_len, h->slots)];
    while(he) {
      if(functions->compare(hash_elem_key(he), he->key_len, key, key_len)) {
        return he->ptr;
      }
      he = he->next;
    }
  }
  return NULL;
}

/**
 * @brief Destroy all entries and free the slot table.
 *
 * Resets the hash so it can be freed or discarded; the Curl_hash struct
 * itself is not freed. Every value is released through its destructor.
 *
 * @param[in,out] h Initialized hash.
 * @post The hash has no slots and must be re-initialized before reuse.
 * @see Curl_hash_clean()
 * @note @unittest 1305, 1602, 1603
 */
void Curl_hash_destroy(struct Curl_hash *h)
{
  DEBUGASSERT(h->init == HASHINIT);
  if(h->table) {
    Curl_hash_clean(h);
    curlx_safefree(h->table);
  }
  DEBUGASSERT(h->size == 0);
  h->slots = 0;
}

/**
 * @brief Remove all entries but keep the hash usable.
 *
 * @param[in,out] h Hash to empty, may be NULL.
 * @post The count is 0 and the slot table is retained.
 * @note @unittest 1602
 */
void Curl_hash_clean(struct Curl_hash *h)
{
  if(h && h->table) {
    struct Curl_hash_element *he, **he_anchor;
    size_t i;
    DEBUGASSERT(h->init == HASHINIT);
    for(i = 0; i < h->slots; ++i) {
      he_anchor = &h->table[i];
      while(*he_anchor) {
        he = *he_anchor;
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
      }
    }
  }
}

/**
 * @brief Get the number of entries in the hash.
 * @param[in] h Initialized hash.
 * @return Number of stored elements.
 */
size_t Curl_hash_count(struct Curl_hash *h)
{
  DEBUGASSERT(h->init == HASHINIT);
  return h->size;
}

/**
 * @brief Remove all entries that pass the comparison function.
 *
 * The callback is called for every entry; entries for which it returns
 * non-zero are unlinked and destroyed.
 *
 * @param[in,out] h    Hash to prune, may be NULL.
 * @param[in]     user Opaque pointer passed as first argument to @p comp.
 * @param[in]     comp Predicate called with (user, value); return non-zero
 *                     to remove the entry. If NULL, all entries are removed.
 * @warning The callback must not modify the hash.
 */
void Curl_hash_clean_with_criterium(struct Curl_hash *h, void *user,
                                    int (*comp)(void *, void *))
{
  size_t i;

  if(!h || !h->table)
    return;

  DEBUGASSERT(h->init == HASHINIT);
  for(i = 0; i < h->slots; ++i) {
    struct Curl_hash_element *he, **he_anchor = &h->table[i];
    while(*he_anchor) {
      /* ask the callback function if we shall remove this entry or not */
      if(!comp || comp(user, (*he_anchor)->ptr)) {
        he = *he_anchor;
        hash_elem_unlink(h, he_anchor, he);
        hash_elem_destroy(h, he);
      }
      else
        he_anchor = &(*he_anchor)->next;
    }
  }
}
