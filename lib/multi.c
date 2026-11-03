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
 * @file
 * @brief Implementation of the libcurl "multi" interface.
 *
 * This file contains the multi handle (struct Curl_multi): the transfer
 * state machine (CURLMstate), the poll/wait helpers, the socket-action
 * API, the per-transfer timeout list and the shared transfer buffers.
 * @note Public curl_multi_*() entry points lock the multi handle via the
 * CURL_MAPI_ENTER()/CURL_MAPI_LEAVE() guards. Curl_*() functions are
 * internal and expect the caller to hold that lock.
 * @see multiif.h, multihandle.h
 * @defgroup multi_internal Multi handle internals
 * @{
 */

#include "curl_setup.h"

#include "urldata.h"
#include "transfer.h"
#include "url.h"
#include "cfilters.h"
#include "connect.h"
#include "progress.h"
#include "curl_share.h"
#include "psl.h"
#include "multiif.h"
#include "multi_ev.h"
#include "sendf.h"
#include "curl_trc.h"
#include "http.h"
#include "select.h"
#include "curlx/wait.h"
#include "conncache.h"
#include "multihandle.h"
#include "sigpipe.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "http_proxy.h"
#include "http2.h"
#include "socketpair.h"
#include "bufref.h"
#include "curlx/strparse.h"

/**
 * @def CURL_XFER_TABLE_SIZE
 * @brief Initial size of the multi->xfers table for a full multi.
 */
#define CURL_XFER_TABLE_SIZE 128

/**
 * @def CURL_SOCKET_HASH_TABLE_SIZE
 * @brief Size of the socket (event) hash table in a multi handle.
 * @note Can be overridden at build time.
 */
#ifndef CURL_SOCKET_HASH_TABLE_SIZE
#define CURL_SOCKET_HASH_TABLE_SIZE 911
#endif

/**
 * @def CURL_CONNECTION_HASH_SIZE
 * @brief Size of the connection pool hash of a multi handle.
 * @note Can be overridden at build time.
 */
#ifndef CURL_CONNECTION_HASH_SIZE
#define CURL_CONNECTION_HASH_SIZE 97
#endif

/**
 * @def CURL_DNS_HASH_SIZE
 * @brief Size of the DNS cache hash of a multi handle.
 * @note Can be overridden at build time.
 */
#ifndef CURL_DNS_HASH_SIZE
#define CURL_DNS_HASH_SIZE 71
#endif

/**
 * @def CURL_TLS_SESSION_SIZE
 * @brief Number of TLS session cache entries of a multi handle.
 * @note Can be overridden at build time.
 */
#ifndef CURL_TLS_SESSION_SIZE
#define CURL_TLS_SESSION_SIZE 25
#endif

static void move_pending_to_connect(struct Curl_multi *multi,
                                    struct Curl_easy *data);
static CURLMcode add_next_timeout(const struct curltime *pnow,
                                  struct Curl_multi *multi,
                                  struct Curl_easy *data);
static void multi_timeout(struct Curl_multi *multi,
                          timediff_t *pexire_offset_us,
                          int *timeout_ms);
static void multi_schedule_pending(struct Curl_multi *multi);
static void multi_xfer_bufs_free(struct Curl_multi *multi);
#ifdef DEBUGBUILD
static void multi_xfer_tbl_dump(struct Curl_multi *multi);
#endif
/* Get the # of transfers current in process/pending. */
static uint32_t multi_xfers_running(struct Curl_multi *multi);

/**
 * @typedef mstate_enter_func
 * @brief Function pointer called once when entering a state.
 * @param[in] data        The transfer that changes state.
 * @param[in] from_state  The state the transfer is leaving.
 * @internal
 */
typedef void (*mstate_enter_func)(struct Curl_easy *data,
                                  CURLMstate from_state);

/**
 * @brief Entry action for MSTATE_CONNECT.
 * Initializes the transfer for a (new) connect attempt.
 * @param[in,out] data        The transfer entering the state.
 * @param[in]     from_state  Previous state (unused).
 * @internal
 */
static void mstate_enter_connect(struct Curl_easy *data,
                                 CURLMstate from_state)
{
  (void)from_state;
  Curl_init_CONNECT(data);
}

/**
 * @brief Entry action for MSTATE_DID.
 * Resets chunking and marks the PRETRANSFER (and, when nothing is to be
 * sent, POSTRANSFER) timers.
 * @param[in,out] data        The transfer entering the state.
 * @param[in]     from_state  Previous state (unused).
 * @internal
 */
static void mstate_enter_did(struct Curl_easy *data,
                             CURLMstate from_state)
{
  (void)from_state;
  data->req.chunk = FALSE;
  Curl_pgrsTime(data, TIMER_PRETRANSFER);
  if(!CURL_REQ_WANT_SEND(data))
    Curl_pgrsTime(data, TIMER_POSTRANSFER);
}

/**
 * @brief Entry action for MSTATE_DONE.
 * Notifies the application via CURLMNOTIFY_EASY_DONE.
 * @param[in,out] data        The transfer entering the state.
 * @param[in]     from_state  Previous state (unused).
 * @internal
 */
static void mstate_enter_done(struct Curl_easy *data,
                              CURLMstate from_state)
{
  (void)from_state;
  CURLM_NTFY(data, CURLMNOTIFY_EASY_DONE);
}

/**
 * @brief Entry action for MSTATE_COMPLETED.
 * Fixes up progress timers when COMPLETED was reached directly, sends the
 * EASY_DONE notification if needed, removes the transfer from the process
 * and pending sets, frees shared buffers when idle, detaches the
 * connection and clears all timers.
 * @param[in,out] data        The transfer entering the state.
 * @param[in]     from_state  The state being left.
 * @pre multi_done() already ran, so data->conn is NULL.
 * @internal
 */
static void mstate_enter_completed(struct Curl_easy *data,
                                   CURLMstate from_state)
{
  /* we sometimes directly jump to COMPLETED, trigger things
   * we then missed. Not when coming from before DO: the transfer
   * failed to resolve/connect and never sent any request. */
  if((from_state >= MSTATE_DO) && (from_state < MSTATE_DID)) {
    Curl_pgrsTime(data, TIMER_PRETRANSFER);
    Curl_pgrsTime(data, TIMER_POSTRANSFER);
    Curl_pgrsTime(data, TIMER_STARTTRANSFER);
  }
  /* multi_done() should have run and detached any connection already */
  DEBUGASSERT(!data->conn);
  Curl_pgrsCompleted(data);
  if(from_state < MSTATE_DONE)
    CURLM_NTFY(data, CURLMNOTIFY_EASY_DONE);
  /* changing to COMPLETED means it is in process and needs to go */
  DEBUGASSERT(Curl_uint32_bset_contains(&data->multi->process, data->mid));
  Curl_uint32_bset_remove(&data->multi->process, data->mid);
  Curl_uint32_bset_remove(&data->multi->pending, data->mid); /* to be sure */

  if(Curl_uint32_bset_empty(&data->multi->process)) {
    /* free the transfer buffer when we have no more active transfers */
    multi_xfer_bufs_free(data->multi);
  }
  /* Important: reset the conn pointer so that we do not point to memory
     that could be freed anytime */
  Curl_detach_connection(data);
  Curl_expire_clear_all(data); /* stop all timers */
}

/**
 * @brief Change the state of a transfer.
 * Always use this function (or the multistate() macro) to change state,
 * to make debugging easier. Runs the matching entry action, if any.
 * @param[in,out] data   The transfer to change.
 * @param[in]     state  The new state.
 * @param[in]     lineno Caller line number (debug builds only).
 * @internal
 */
static void mstate(struct Curl_easy *data, CURLMstate state
#ifdef DEBUGBUILD
                   , int lineno
#endif
)
{
  CURLMstate oldstate = data->mstate;
  static const mstate_enter_func state_enter[MSTATE_LAST] = {
    NULL,                      /* INIT */
    NULL,                      /* PENDING */
    NULL,                      /* SETUP */
    mstate_enter_connect,      /* CONNECT */
    NULL,                      /* CONNECTING */
    NULL,                      /* PROTOCONNECT */
    NULL,                      /* PROTOCONNECTING */
    NULL,                      /* DO */
    NULL,                      /* DOING */
    NULL,                      /* DOING_MORE */
    mstate_enter_did,          /* DID */
    NULL,                      /* PERFORMING */
    NULL,                      /* RATELIMITING */
    mstate_enter_done,         /* DONE */
    mstate_enter_completed,    /* COMPLETED */
    NULL                       /* MSGSENT */
  };

  if(oldstate == state)
    /* do not bother when the new state is the same as the old state */
    return;

#ifdef DEBUGBUILD
  NOVERBOSE((void)lineno);
  CURL_TRC_M(data, "-> [%s] (line %d)", CURL_MSTATE_NAME(state), lineno);
#else
  CURL_TRC_M(data, "-> [%s]", CURL_MSTATE_NAME(state));
#endif

  /* really switching state */
  data->mstate = state;
  if(state_enter[state])
    state_enter[state](data, oldstate);
}

#ifndef DEBUGBUILD
#define multistate(x, y) mstate(x, y)
#else
/**
 * @def multistate
 * @brief Change transfer state; passes __LINE__ in debug builds.
 * @see mstate()
 */
#define multistate(x, y) mstate(x, y, __LINE__)
#endif

/**
 * @brief Destructor for multi->proto_hash entries.
 * Should never be called as elements MUST be added with their own
 * destructor.
 * @param[in] p  The hash entry (unused beyond a debug assert).
 * @internal
 */
static void ph_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(!p);
}

/**
 * @brief Queue a completion message for a finished transfer.
 * Called when a transfer is completed. Marks its message as unread.
 * @param[in,out] multi  The multi handle owning the message list.
 * @param[in,out] data   The completed transfer.
 * @internal
 */
static void multi_addmsg(struct Curl_multi *multi, struct Curl_easy *data)
{
  if(Curl_uint32_bset_empty(&multi->msgsent))
    CURLM_NTFY(multi->admin, CURLMNOTIFY_INFO_READ);
  Curl_uint32_bset_add(&multi->msgsent, data->mid);
}

static void multi_timeouts_init(struct Curl_easy *data);

/**
 * @brief Create a multi handle with explicit hash/table sizes.
 * @param[in] xfer_table_size  Initial size of the transfer table.
 * @param[in] ev_hashsize      Size of the socket event hash.
 * @param[in] chashsize        Size of the connection pool hash.
 * @param[in] dnssize          Size of the DNS cache hash.
 * @param[in] sesssize         Size of the TLS session cache.
 * @return The new multi handle, or NULL on out of memory.
 * @note On failure everything allocated so far is freed again.
 * @see curl_multi_init()
 */
struct Curl_multi *Curl_multi_handle(uint32_t xfer_table_size,
                                     size_t ev_hashsize,  /* event hash */
                                     size_t chashsize, /* connection hash */
                                     size_t dnssize,   /* dns hash */
                                     size_t sesssize)  /* TLS session cache */
{
  struct curltime created;
  struct Curl_multi *multi = curlx_calloc(1, sizeof(struct Curl_multi));

  if(!multi)
    return NULL;

  multi->magic = CURLMULTI_MAGIC_NUMBER;

  /* Initialisation order is important here!
   * easy_init() does a lazy check on curl_global_init() which sets
   * up platform specific things we need. For example calling curlx_pnow()
   * before this is not safe. */
  multi->admin = curl_easy_init();
  if(!multi->admin) {
    curlx_free(multi);
    return NULL;
  }
  multi->admin->multi = multi;
  multi->admin->state.internal = TRUE;

  /* Now we can use curlx_* things safely */
  curlx_pnow(&created);
  Curl_timeouts_init(&multi->timeouts, &created);
  multi_timeouts_init(multi->admin);

  Curl_dnscache_init(&multi->dnscache, dnssize);
  Curl_mntfy_init(multi);
  Curl_multi_ev_init(multi, ev_hashsize);
  Curl_uint32_tbl_init(&multi->xfers);
  Curl_uint32_bset_init(&multi->process);
  Curl_uint32_bset_init(&multi->dirty);
  Curl_uint32_bset_init(&multi->pending);
  Curl_uint32_bset_init(&multi->msgsent);
  Curl_hash_init(&multi->proto_hash, 23, CURL_HASH_TYPE_BYTES, ph_freeentry);
  Curl_cshutdn_init(&multi->cshutdn);

  multi->multiplexing = TRUE;
  multi->max_concurrent_streams = 100;
#ifdef ENABLE_WAKEUP
  multi->wakeup_pair[0] = CURL_SOCKET_BAD;
  multi->wakeup_pair[1] = CURL_SOCKET_BAD;
#endif
#ifdef ENABLE_INTERNAL_WAKEUP
  multi->wakeup_internal[0] = CURL_SOCKET_BAD;
  multi->wakeup_internal[1] = CURL_SOCKET_BAD;
#endif

  if(Curl_uint32_bset_resize(&multi->process, xfer_table_size) ||
     Curl_uint32_bset_resize(&multi->pending, xfer_table_size) ||
     Curl_uint32_bset_resize(&multi->dirty, xfer_table_size) ||
     Curl_uint32_bset_resize(&multi->msgsent, xfer_table_size) ||
     Curl_uint32_tbl_resize(&multi->xfers, xfer_table_size))
    goto error;

#ifdef DEBUGBUILD
  {
    const char *p;
    if(getenv("CURL_DEBUG"))
      multi->admin->set.verbose = TRUE;
    p = getenv("CURL_DBG_MAX_TOTAL_CONNECTIONS");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, UINT32_MAX)) {
        multi->max_total_connections = (uint32_t)l;
      }
    }
  }
#endif
  Curl_uint32_tbl_add(&multi->xfers, multi->admin, &multi->admin->mid);
  Curl_uint32_bset_add(&multi->process, multi->admin->mid);

  Curl_cpool_init(&multi->cpool, NULL, chashsize);

#ifdef USE_SSL
  if(Curl_ssl_scache_create(sesssize, 2, &multi->ssl_scache))
    goto error;
#else
  (void)sesssize;
#endif

#ifdef USE_WINSOCK
  multi->wsa_event = WSACreateEvent();
  if(multi->wsa_event == WSA_INVALID_EVENT)
    goto error;
#endif
#ifdef ENABLE_WAKEUP
  /* When enabled, rely on this to work. We ignore this in previous
   * versions, but that seems an unnecessary complication. */
  if(Curl_wakeup_init(multi->wakeup_pair, TRUE) < 0)
    goto error;
#endif
#ifdef ENABLE_INTERNAL_WAKEUP
  if(Curl_wakeup_init(multi->wakeup_internal, TRUE) < 0)
    goto error;
#endif

  if(Curl_probeipv6(multi))
    goto error;

#ifdef USE_RESOLV_THREADED
  if(xfer_table_size < CURL_XFER_TABLE_SIZE) { /* easy multi */
    if(Curl_async_thrdd_multi_init(multi, 0, 2, 10))
      goto error;
  }
  else { /* real multi handle */
    if(Curl_async_thrdd_multi_init(multi, 0, 20, 2000))
      goto error;
  }
#endif

  return multi;

error:

#ifdef USE_RESOLV_THREADED
  Curl_async_thrdd_multi_destroy(multi, TRUE);
#endif
  Curl_multi_ev_cleanup(multi);
  Curl_hash_destroy(&multi->proto_hash);
  Curl_dnscache_destroy(&multi->dnscache);
  Curl_cpool_destroy(&multi->cpool, multi->admin);
  Curl_cshutdn_destroy(&multi->cshutdn, multi->admin);
#ifdef USE_SSL
  Curl_ssl_scache_destroy(multi->ssl_scache);
#endif
  if(multi->admin) {
    Curl_multi_ev_xfer_done(multi, multi->admin);
    multi->admin->multi = NULL;
    Curl_close(&multi->admin);
  }
  Curl_mntfy_cleanup(multi);

  Curl_uint32_bset_destroy(&multi->process);
  Curl_uint32_bset_destroy(&multi->dirty);
  Curl_uint32_bset_destroy(&multi->pending);
  Curl_uint32_bset_destroy(&multi->msgsent);
  Curl_uint32_tbl_destroy(&multi->xfers);
#ifdef ENABLE_WAKEUP
  Curl_wakeup_destroy(multi->wakeup_pair);
#endif
#ifdef ENABLE_INTERNAL_WAKEUP
  Curl_wakeup_destroy(multi->wakeup_internal);
#endif

  curlx_free(multi);
  return NULL;
}

/**
 * @brief Create a multi handle with default sizes.
 * @return A new CURLM handle, or NULL on failure.
 * @see curl_multi_cleanup()
 */
CURLM *curl_multi_init(void)
{
  return Curl_multi_handle(CURL_XFER_TABLE_SIZE,
                           CURL_SOCKET_HASH_TABLE_SIZE,
                           CURL_CONNECTION_HASH_SIZE,
                           CURL_DNS_HASH_SIZE,
                           CURL_TLS_SESSION_SIZE);
}

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
/**
 * @brief Warn when a verbose build is used with a multi handle.
 * Only compiled for debug builds with verbose support.
 * @param[in] multi  The multi handle.
 * @param[in] data   The transfer to emit the info message for.
 * @internal
 */
static void multi_warn_debug(struct Curl_multi *multi, struct Curl_easy *data)
{
  if(!multi->warned) {
    infof(data, "!!! WARNING !!!");
    infof(data, "This is a debug build of libcurl, "
                "do not use in production.");
    multi->warned = TRUE;
  }
}
#else
#define multi_warn_debug(x, y) Curl_nop_stmt
#endif

/**
 * @brief Tell if a transfer is currently connecting.
 * @param[in] data  The transfer to inspect.
 * @return TRUE if it is in the CONNECT or CONNECTING state.
 */
bool Curl_is_connecting(struct Curl_easy *data)
{
  return data->mstate < MSTATE_DO;
}

/**
 * @brief Set up the internal wakeup mechanism of the multi handle.
 * Creates the socketpair or eventfd used by curl_multi_wakeup(), if the
 * platform supports it.
 * @param[in,out] multi  The multi handle.
 * @return CURLM_OK, or CURLM_WAKEUP_FAILURE if setup failed.
 * @internal
 */
static CURLMcode multi_assess_wakeup(struct Curl_multi *multi)
{
#ifdef ENABLE_INTERNAL_WAKEUP
  if(multi->socket_cb)
    return Curl_multi_ev_assess_xfer(multi, multi->admin);
#else
  (void)multi;
#endif
  return CURLM_OK;
}

/**
 * @brief Register a transfer in the multi handle's transfer table.
 * Assigns a transfer id (mid) and grows the table when needed.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer to add.
 * @return CURLM_OK, CURLM_OUT_OF_MEMORY or CURLM_ADDED_ALREADY.
 * @internal
 */
static CURLMcode multi_xfers_add(struct Curl_multi *multi,
                                 struct Curl_easy *data)
{
  uint32_t capacity = Curl_uint32_tbl_capacity(&multi->xfers);
  uint32_t new_size = 0;
  /* Prepare to make this into a CURLMOPT_MAX_TRANSFERS, because some
   * applications may want to prevent a run-away of their memory use. */
  /* UINT_MAX is our "invalid" id, do not let the table grow up to that. */
  const uint32_t max_capacity = UINT_MAX - 1;

  if(capacity < max_capacity) {
    /* We want `multi->xfers` to have "sufficient" free rows, so that we do
     * not have to reuse the `mid` from a removed easy right away.
     * Check if an 8th of the capacity is still free */
    uint32_t used = Curl_uint32_tbl_count(&multi->xfers);
    uint32_t unused = capacity - used;
    uint32_t min_unused = CURLMAX(capacity >> 3, 4);
    if(unused < min_unused) {
      /* Grow by 50% of current capacity, in range of [128, 2048],
       * which means the table grows max by 16kb on 64-bit arch. */
      uint32_t growth = CURLMIN(CURLMAX(capacity >> 1, 128), 2048);
      /* Make sure the uint arithmetic here works on the corner
       * cases where we are close to max_capacity or UINT_MAX */
      if((max_capacity - growth) <= capacity)
        new_size = max_capacity;
      else
        new_size = capacity + growth;
    }
  }

  if(new_size > capacity) {
    /* Grow the bitsets first. Should one fail, we do not need
     * to downsize the already resized ones. The sets continue
     * to work properly when larger than the table, but not
     * the other way around. */
    CURL_TRC_M(data, "increasing xfer table size to %u", new_size);
    if(Curl_uint32_bset_resize(&multi->process, new_size) ||
       Curl_uint32_bset_resize(&multi->dirty, new_size) ||
       Curl_uint32_bset_resize(&multi->pending, new_size) ||
       Curl_uint32_bset_resize(&multi->msgsent, new_size) ||
       Curl_uint32_tbl_resize(&multi->xfers, new_size))
      return CURLM_OUT_OF_MEMORY;
  }

  /* Insert the easy into the table now */
  if(!Curl_uint32_tbl_add(&multi->xfers, data, &data->mid)) {
    /* MUST only happen when table is full */
    DEBUGASSERT(Curl_uint32_tbl_capacity(&multi->xfers) <=
                Curl_uint32_tbl_count(&multi->xfers));
    return CURLM_OUT_OF_MEMORY;
  }
  return CURLM_OK;
}

/**
 * @brief Add a transfer to a multi handle (internal).
 * Sets up the admin handle on first use, registers the transfer, clones
 * timeouts, and moves it to MSTATE_INIT.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer to add.
 * @return CURLM_OK or a CURLMcode error:
 *  - CURLM_BAD_HANDLE for invalid handles
 *  - CURLM_ADDED_ALREADY if already part of a multi
 *  - CURLM_RECURSIVE_API_CALL if called from a callback
 *  - CURLM_OUT_OF_MEMORY on allocation failure
 * @warning The transfer must not be used by another thread meanwhile.
 * @see Curl_multi_remove_handle()
 */
CURLMcode Curl_multi_add_handle(struct Curl_multi *multi,
                                struct Curl_easy *data)
{
  CURLMcode mresult;

  /* Prevent users from adding same easy handle more than once and prevent
     adding to more than one multi stack */
  if(data->multi)
    return CURLM_ADDED_ALREADY;

  if(multi->dead) {
    /* a "dead" handle cannot get added transfers while any existing easy
       handles are still alive - but if there are none alive anymore, it is
       fine to start over and unmark the "deadness" of this handle.
       This means only the admin handle MUST be present. */
    if((Curl_uint32_tbl_count(&multi->xfers) != 1) ||
       !Curl_uint32_tbl_contains(&multi->xfers, 0))
      return CURLM_ABORTED_BY_CALLBACK;
    multi->dead = FALSE;
    Curl_uint32_bset_clear(&multi->process);
    Curl_uint32_bset_clear(&multi->dirty);
    Curl_uint32_bset_clear(&multi->pending);
    Curl_uint32_bset_clear(&multi->msgsent);
  }

  if(data->multi_easy) {
    /* if this easy handle was previously used for curl_easy_perform(), there
       is a private multi handle here that we can kill */
    curl_multi_cleanup(data->multi_easy);
    data->multi_easy = NULL;
  }

  /* Insert the easy into the multi->xfers table, assigning it a `mid`. */
  if(multi_xfers_add(multi, data))
    return CURLM_OUT_OF_MEMORY;

  /* Initialize timeouts for this handle */
  multi_timeouts_init(data);

  /*
   * No failure allowed in this function beyond this point. No modification
   * of easy nor multi handle allowed before this except for potential
   * multi's connection pool growing which will not be undone in this
   * function no matter what.
   */
  if(data->set.errorbuffer)
    data->set.errorbuffer[0] = 0;

  data->state.os_errno = 0;

  /* make the Curl_easy refer back to this multi handle - before
     Curl_expire() is called. */
  data->multi = multi;

  /* set the easy handle */
  multistate(data, MSTATE_INIT);
  /* not yet passed INIT state */
  data->state.really_alive = FALSE;

#ifdef USE_LIBPSL
  /* Do the same for PSL. */
  if(data->share && (data->share->specifier & (1 << CURL_LOCK_DATA_PSL)))
    data->psl = &data->share->psl;
  else
    data->psl = &multi->psl;
#endif

  /* add the easy handle to the process set */
  Curl_uint32_bset_add(&multi->process, data->mid);
  ++multi->xfers_alive;
  ++multi->xfers_total_ever;

  Curl_cpool_xfer_init(data);
  multi_warn_debug(multi, data);

  /* Make sure the new handle will run */
  Curl_multi_mark_dirty(data);

  /* Necessary in event based processing, where dirty handles trigger
   * a timeout callback invocation. */
  mresult = Curl_update_timer(multi);
  if(mresult) {
    /* undo the additions above */
    Curl_uint32_bset_remove(&multi->process, data->mid);
    Curl_uint32_bset_remove(&multi->dirty, data->mid);
    --multi->xfers_alive;
    data->multi = NULL; /* not anymore */
    Curl_uint32_tbl_remove(&multi->xfers, data->mid);
    data->mid = UINT32_MAX;
    return mresult;
  }

  /* The admin handle only ever has default timeouts set. To improve the
     state somewhat we clone the timeouts from each added handle so that the
     admin handle always has the same timeouts as the most recently added
     easy handle. */
  multi->admin->set.timeout = data->set.timeout;
  multi->admin->set.server_response_timeout =
    data->set.server_response_timeout;
  multi->admin->set.no_signal = data->set.no_signal;

  CURL_TRC_M(data, "added to multi, mid=%u, running=%u, total=%u",
             data->mid, multi_xfers_running(multi),
             Curl_uint32_tbl_count(&multi->xfers));
  return CURLM_OK;
}

/**
 * @brief Add an easy handle to a multi handle (public API).
 * @param[in,out] m     The multi handle.
 * @param[in,out] curl  The easy handle to add.
 * @return CURLM_OK on success, otherwise a CURLMcode error.
 * @note The easy handle must not already belong to another multi handle.
 * @see curl_multi_remove_handle()
 */
CURLMcode curl_multi_add_handle(CURLM *m, CURL *curl)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_add_handle, &mresult)) {
    struct Curl_easy *data = curl;
    /* Verify that we got a somewhat good easy handle too */
    if(!GOOD_EASY_HANDLE(data) || data->state.internal)
      mresult = CURLM_BAD_EASY_HANDLE;
    else
      mresult = Curl_multi_add_handle(m, data);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @struct multi_done_ctx
 * @brief Context passed to multi_done_locked() through the conn pool.
 */
struct multi_done_ctx {
  BIT(premature);
};

/**
 * @brief Decide whether a connection must be closed after a transfer.
 * @param[in] conn       The connection used by the transfer.
 * @param[in] data       The transfer that is done with it.
 * @param[in] premature  TRUE if the transfer ended before completion.
 * @return TRUE if the connection should be closed, FALSE if it may be
 *         kept for reuse.
 * @internal
 */
static bool multi_conn_should_close(struct connectdata *conn,
                                    struct Curl_easy *data,
                                    bool premature)
{
  /* if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of everything else. */
  if(conn->bits.close)
    return TRUE;

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has forced
     us to close this connection. This is ignored for requests taking place in
     a NEGOTIATE authentication handshake. */
  if(data->set.reuse_forbid
#ifdef USE_SPNEGO
     && !(conn->http_negotiate_state == CURL_NEGO_AUTH_RECV ||
          conn->proxy_negotiate_state == CURL_NEGO_AUTH_RECV)
#endif
    )
    return TRUE;

  /* Unless this connection is for a "connect-only" transfer, it
   * needs to be closed if the protocol handler does not support reuse. */
  if(!data->set.connect_only && conn->scheme &&
     !(conn->scheme->flags & PROTOPT_CONN_REUSE))
    return TRUE;

  /* if premature is TRUE, it means this connection was said to be DONE before
     the entire request operation is complete and thus we cannot know in what
     state it is for reusing, so we are forced to close it. In a perfect world
     we can add code that keep track of if we really must close it here or not,
     but currently we have no such detail knowledge. */
  if(premature && !Curl_conn_is_multiplex(conn, FIRSTSOCKET))
    return TRUE;

  return FALSE;
}

/**
 * @brief Finish a transfer's use of a connection, pool lock held.
 * Runs the protocol done handler and either closes the connection or
 * returns it to the pool.
 * @param[in,out] data      The transfer.
 * @param[in,out] conn      The connection to hand back.
 * @param[in]     userdata  A struct multi_done_ctx.
 * @param[in]     pnow      The current time.
 * @return A cpool_do_result telling the pool whether the connection was
 *         removed.
 * @pre The connection pool lock is held.
 * @internal
 */
static cpool_do_result multi_done_locked(struct Curl_easy *data,
                                         struct connectdata *conn,
                                         void *userdata,
                                         const struct curltime *pnow)
{
  struct multi_done_ctx *mdctx = userdata;

  (void)pnow;
  CURL_TRC_M(data, "multi_done_locked, in use=%u", conn->attached_xfers);
  if(CONN_INUSE(conn)) {
    /* Stop if still used. */
    CURL_TRC_M(data, "Connection still in use %u, no more multi_done now!",
               conn->attached_xfers);
    return CPOOL_DO_KEEP;
  }

  if(multi_conn_should_close(conn, data, (bool)mdctx->premature)) {
    CURL_TRC_M(data, "multi_done, terminating conn #%" FMT_OFF_T " to %s:%u, "
               "forbid=%d, close=%d, premature=%d, conn_multiplex=%d",
               conn->connection_id, conn->origin->user_hostname,
               conn->origin->port,
               data->set.reuse_forbid, conn->bits.close, mdctx->premature,
               Curl_conn_is_multiplex(conn, FIRSTSOCKET));
    connclose(conn);
    return mdctx->premature ? CPOOL_DO_TERMINATE : CPOOL_DO_CLOSE;
  }
  else if(!Curl_conn_get_max_concurrent(data, conn, FIRSTSOCKET)) {
    CURL_TRC_M(data, "multi_done, conn #%" FMT_OFF_T " to %s:%u was shutdown"
               " by server, not reusing", conn->connection_id,
               conn->origin->user_hostname, conn->origin->port);
    connclose(conn);
    return mdctx->premature ? CPOOL_DO_TERMINATE : CPOOL_DO_CLOSE;
  }
  else {
    return CPOOL_DO_IDLE;
  }
}

/**
 * @brief Called when a transfer is done with its connection.
 * Handles both successful and failed transfers: closes or releases the
 * connection, flushes progress and resets per-request state.
 * @param[in,out] data       The transfer.
 * @param[in]     status     Result so far; an error if this is called
 *                           after an error was detected.
 * @param[in]     premature  TRUE if the transfer did not finish normally.
 * @return The final CURLcode, possibly replaced by a done-handler error.
 * @internal
 */
static CURLcode multi_done(struct Curl_easy *data,
                           CURLcode status,  /* an error if this is called
                                                after an error was detected */
                           bool premature)
{
  CURLcode result;
  struct connectdata *conn = data->conn;
  const struct curltime *pnow = Curl_pgrs_now(data);

  CURL_TRC_M(data, "multi_done: status: %d prem: %d done: %d",
             (int)status, (int)premature, data->state.done);

  if(data->state.done) {
    /* Stop if multi_done() has already been called */
    return CURLE_OK;
  }
  data->state.done = TRUE; /* called now! */

  /* Shut down any ongoing async resolver operation. */
  Curl_resolv_shutdown_all(data);

  /* Cleanup possible redirect junk */
  curlx_safefree(data->req.newurl);
  curlx_safefree(data->req.location);

  switch(status) {
  case CURLE_ABORTED_BY_CALLBACK:
  case CURLE_READ_ERROR:
  case CURLE_WRITE_ERROR:
    /* When we are aborted due to a callback return code it has to be counted
       as premature as there is trouble ahead if we do not. We have many
       callbacks and protocols work differently, we could potentially do this
       more fine-grained in the future. */
    premature = TRUE;
    FALLTHROUGH();
  default:
    break;
  }

  /* this calls the protocol-specific function pointer previously set */
  if(conn && conn->scheme->run->done && (data->mstate >= MSTATE_PROTOCONNECT))
    result = conn->scheme->run->done(data, status, premature);
  else
    result = status;

  if(data->mstate > MSTATE_CONNECTING &&
     (result != CURLE_ABORTED_BY_CALLBACK)) {
    /* avoid this if
     * - the transfer has not connected
     * - we already aborted by callback to avoid this calling another callback
     */
    int rc = Curl_pgrsDone(data, pnow);
    if(!result && rc)
      result = CURLE_ABORTED_BY_CALLBACK;
  }

  /* Make sure that transfer client writes are really done now. */
  result = Curl_1st_fatal(result, Curl_xfer_write_done(data, premature));

  if(!result)
    result = Curl_req_done(&data->req, data, premature);

  if(conn) {
    /* Detach connection and decide what to do with it. */
    struct multi_done_ctx mdctx;

    /* Inform connection filters that this transfer is done and they
     * need to give up any references to `data`. */
    Curl_conn_ev_data_done(data, premature);
    Curl_detach_connection(data);
    Curl_dnscache_prune(data, pnow);

    memset(&mdctx, 0, sizeof(mdctx));
    mdctx.premature = premature;
    Curl_cpool_return(data, conn, multi_done_locked, &mdctx, pnow);

    if(data->multi)
      multi_schedule_pending(data->multi);
  }

  /* flush the netrc cache */
  Curl_netrc_cleanup(&data->state.netrc);
  return result;
}

/**
 * @brief Remove a transfer from a multi handle (internal).
 * Marks a running transfer as done, drops its connection, cancels timers
 * and removes it from the transfer table and queues.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer to remove.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_RECURSIVE_API_CALL.
 * @warning Pending completion messages for the handle are discarded.
 * @see Curl_multi_add_handle()
 */
CURLMcode Curl_multi_remove_handle(struct Curl_multi *multi,
                                   struct Curl_easy *data)
{
  CURLMcode mresult;
  bool premature;
  uint32_t mid;

  /* Prevent users from trying to remove same easy handle more than once */
  if(!data->multi)
    return CURLM_OK; /* it is already removed so let's say it is fine! */

  /* Prevent users from trying to remove an easy handle from the wrong multi */
  if(data->multi != multi)
    return CURLM_BAD_EASY_HANDLE;

  if(data->mid == UINT32_MAX) {
    DEBUGASSERT(0);
    return CURLM_INTERNAL_ERROR;
  }
  if(Curl_uint32_tbl_get(&multi->xfers, data->mid) != data) {
    DEBUGASSERT(0);
    return CURLM_INTERNAL_ERROR;
  }

  premature = (data->mstate < MSTATE_COMPLETED);

  if(data->conn) {
    /* If the 'state' is not INIT or COMPLETED, we might need to do something
       nice to put the easy_handle in a good known state when this returns. */
    if(premature && (data->mstate > MSTATE_DO))
      streamclose(data->conn);

    /* multi_done() clears the association between the easy handle and the
       connection.
       Note that this ignores the return code because there is
       nothing really useful to do with it anyway! */
    (void)multi_done(data, data->result, premature);
  }

  /* The timer must be shut down before data->multi is set to NULL, else
     data's splaynode would remain in the splay tree after curl_easy_cleanup is
     called. Do it after multi_done() in case that sets another time! */
  Curl_expire_clear_all(data);

  /* In MSGSENT, it was deducted from `multi->xfers_alive` already. */
  if(data->mstate != MSTATE_MSGSENT)
    --multi->xfers_alive;

  if(data->state.really_alive) {
    data->state.really_alive = FALSE;
    --multi->xfers_really_alive;
    if(!multi->xfers_really_alive)
      (void)multi_assess_wakeup(multi);
  }

  Curl_wildcard_dtor(&data->wildcard);

  data->mstate = MSTATE_COMPLETED;

  /* Remove the association between the connection and the handle */
  Curl_detach_connection(data);

  /* Tell event handling that this transfer is definitely going away */
  Curl_multi_ev_xfer_done(multi, data);

  if(data->set.connect_only) {
    if(data->multi_easy) {
      if(data->state.last_conn_id != -1) {
        /* Mark any connect-only connection for closure */
        struct connectdata *conn;
        (void)Curl_getconnectinfo(data, &conn);
        if(conn && conn->bits.connect_only)
          connclose(conn);
      }
    }
    else {
      /* This removes a handle that was part the multi interface that used
         CONNECT_ONLY, that connection is now left alive but since this handle
         has bits.close set nothing can use that connection anymore and it is
         forbidden from reuse. This easy handle cannot find the connection
         anymore once removed from the multi handle

         Better close the connection here, at once. */
      struct connectdata *conn;
      (void)Curl_getconnectinfo(data, &conn);
      if(conn)
        Curl_conn_close(data, conn, TRUE);
    }
  }

#ifdef USE_LIBPSL
  /* Remove the PSL association. */
  if(data->psl == &multi->psl)
    data->psl = NULL;
#endif

  /* clear the association to this multi handle */
  mid = data->mid;
  DEBUGASSERT(Curl_uint32_tbl_contains(&multi->xfers, mid));
  Curl_uint32_tbl_remove(&multi->xfers, mid);
  Curl_uint32_bset_remove(&multi->process, mid);
  Curl_uint32_bset_remove(&multi->dirty, mid);
  Curl_uint32_bset_remove(&multi->pending, mid);
  Curl_uint32_bset_remove(&multi->msgsent, mid);
  data->multi = NULL;
  data->mid = UINT32_MAX;
  data->master_mid = UINT32_MAX;

  /* A pending transfer *might* be able to run now. */
  multi_schedule_pending(multi);
  mresult = Curl_update_timer(multi);
  if(mresult)
    return mresult;

  mresult = multi_assess_wakeup(multi);
  if(mresult) {
    failf(data, "error enabling wakeup listening: %d", mresult);
    return mresult;
  }

  CURL_TRC_M(data, "removed from multi, mid=%u, running=%u, total=%u",
             mid, multi_xfers_running(multi),
             Curl_uint32_tbl_count(&multi->xfers));
  return CURLM_OK;
}

/**
 * @brief Remove an easy handle from a multi handle (public API).
 * @param[in,out] m     The multi handle.
 * @param[in,out] curl  The easy handle to remove.
 * @return CURLM_OK on success, otherwise a CURLMcode error.
 * @see curl_multi_add_handle()
 */
CURLMcode curl_multi_remove_handle(CURLM *m, CURL *curl)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_remove_handle, &mresult)) {
    struct Curl_easy *data = curl;
    if(!GOOD_EASY_HANDLE(data) || data->state.internal)
      mresult = CURLM_BAD_EASY_HANDLE;
    else
      mresult = Curl_multi_remove_handle(m, data);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Tell if the application asked for multiplexing.
 * @param[in] multi  The multi handle (may be NULL).
 * @return TRUE if CURLMOPT_PIPELINING enables multiplexing.
 */
bool Curl_multiplex_wanted(const struct Curl_multi *multi)
{
  return multi && multi->multiplexing;
}

/**
 * @brief Remove the given transfer from its connection.
 * This is the only function that should clear data->conn. It may
 * occasionally be called with data->conn already cleared.
 * @param[in,out] data  The transfer to detach.
 * @post data->conn is NULL.
 * @see Curl_attach_connection()
 */
void Curl_detach_connection(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  if(conn) {
    /* this should never happen, prevent underflow */
    DEBUGASSERT(conn->attached_xfers);
    if(conn->attached_xfers) {
      conn->attached_xfers--;
      if(!conn->attached_xfers)
        conn->attached_multi = NULL;
    }
  }
  data->conn = NULL;
}

/**
 * @brief Attach a transfer to a connection.
 * This is the only function that should assign data->conn.
 * @param[in,out] data     The transfer.
 * @param[in,out] conn     The connection to attach to.
 * @param[in]     matched  TRUE if the transfer's properties match this
 *                         connection; FALSE for a temporary attach for
 *                         maintenance.
 * @pre data is not attached to another connection.
 * @see Curl_detach_connection()
 */
void Curl_attach_connection(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool matched)
{
  DEBUGASSERT(data);
  DEBUGASSERT(!data->conn);
  DEBUGASSERT(conn);
  DEBUGASSERT(conn->attached_xfers < UINT32_MAX);
  data->conn = conn;
  if(matched) {
    data->state.last_conn_id = conn->connection_id;
    data->state.last_cpid = conn->cpid;
  }
  else
    DEBUGASSERT(!data->mid); /* admin handle */
  conn->attached_xfers++;
  /* all attached transfers must be from the same multi */
  if(!conn->attached_multi)
    conn->attached_multi = data->multi;
  DEBUGASSERT(conn->attached_multi == data->multi);

  if(conn->scheme && conn->scheme->run->attach)
    conn->scheme->run->attach(data, conn);
}

/**
 * @brief Adjust a pollset for rate limits and pauses.
 * Removes the directions that are paused or rate limited.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to adjust.
 * @return CURLE_OK, or an error if the pollset could not be changed.
 * @internal
 */
static CURLcode multi_adjust_pollset(struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;

  if(ps->n) {
    bool send_blocked, recv_blocked;

    recv_blocked = (Curl_rlimit_avail(&data->progress.dl.rlimit, NULL) <= 0);
    send_blocked = (Curl_rlimit_avail(&data->progress.ul.rlimit, NULL) <= 0);
    if(send_blocked || recv_blocked) {
      int i;
      for(i = 0; i <= SECONDARYSOCKET; ++i) {
        curl_socket_t sock = data->conn->sock[i];
        if(sock == CURL_SOCKET_BAD)
          continue;
        if(recv_blocked && Curl_pollset_want_recv(data, ps, sock)) {
          result = Curl_pollset_remove_in(data, ps, sock);
          if(result)
            break;
        }
        if(send_blocked && Curl_pollset_want_send(data, ps, sock)) {
          result = Curl_pollset_remove_out(data, ps, sock);
          if(result)
            break;
        }
      }
    }

    /* Not blocked and wanting to receive. If there is data pending
     * in the connection filters, make transfer run again. */
    if(!recv_blocked &&
       ((Curl_pollset_want_recv(data, ps, data->conn->sock[FIRSTSOCKET]) &&
         Curl_conn_data_pending(data, FIRSTSOCKET)) ||
        (Curl_pollset_want_recv(data, ps, data->conn->sock[SECONDARYSOCKET]) &&
         Curl_conn_data_pending(data, SECONDARYSOCKET)))) {
      CURL_TRC_M(data, "pollset[] has POLLIN, but there is still "
                 "buffered input -> mark as dirty");
      Curl_multi_mark_dirty(data);
    }
  }
  return result;
}

/**
 * @brief Pollset for transfers in the CONNECTING state.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to fill.
 * @return CURLE_OK or an error from the connection filters.
 * @internal
 */
static CURLcode mstate_connecting_pollset(struct Curl_easy *data,
                                          struct easy_pollset *ps)
{
  struct connectdata *conn = data->conn;
  curl_socket_t sockfd;
  CURLcode result = CURLE_OK;

  if(Curl_xfer_recv_is_paused(data))
    return CURLE_OK;
  /* If a socket is set, receiving is default. If the socket
   * has not been determined yet (eyeballing), always ask the
   * connection filters for what to monitor. */
  sockfd = Curl_conn_get_first_socket(data);
  if(sockfd != CURL_SOCKET_BAD) {
    result = Curl_pollset_change(data, ps, sockfd, CURL_POLL_IN, 0);
    if(!result)
      result = multi_adjust_pollset(data, ps);
  }
  if(!result)
    result = Curl_conn_adjust_pollset(data, conn, ps);
  return result;
}

/**
 * @brief Pollset for transfers in the protocol connect states.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to fill.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode mstate_protocol_pollset(struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  if(conn->scheme->run->proto_pollset)
    result = conn->scheme->run->proto_pollset(data, ps);
  else {
    curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
    if(sockfd != CURL_SOCKET_BAD) {
      /* Default is to wait to something from the server */
      result = Curl_pollset_change(data, ps, sockfd, CURL_POLL_IN, 0);
    }
  }
  if(!result)
    result = multi_adjust_pollset(data, ps);
  if(!result)
    result = Curl_conn_adjust_pollset(data, conn, ps);
  return result;
}

/**
 * @brief Pollset for transfers in the DOING state.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to fill.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode mstate_do_pollset(struct Curl_easy *data,
                                  struct easy_pollset *ps)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  if(conn->scheme->run->doing_pollset)
    result = conn->scheme->run->doing_pollset(data, ps);
  else if(CONN_SOCK_IDX_VALID(conn->send_idx)) {
    /* Default is that we want to send something to the server */
    result = Curl_pollset_add_out(data, ps, conn->sock[conn->send_idx]);
  }
  if(!result)
    result = multi_adjust_pollset(data, ps);
  if(!result)
    result = Curl_conn_adjust_pollset(data, conn, ps);
  return result;
}

/**
 * @brief Pollset for transfers in the DOING_MORE state.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to fill.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode mstate_domore_pollset(struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  if(conn->scheme->run->domore_pollset)
    result = conn->scheme->run->domore_pollset(data, ps);
  else if(CONN_SOCK_IDX_VALID(conn->send_idx)) {
    /* Default is that we want to send something to the server */
    result = Curl_pollset_add_out(data, ps, conn->sock[conn->send_idx]);
  }
  if(!result)
    result = multi_adjust_pollset(data, ps);
  if(!result)
    result = Curl_conn_adjust_pollset(data, conn, ps);
  return result;
}

/**
 * @brief Pollset for transfers in the PERFORMING state.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to fill.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode mstate_perform_pollset(struct Curl_easy *data,
                                       struct easy_pollset *ps)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  if(conn->scheme->run->perform_pollset)
    result = conn->scheme->run->perform_pollset(data, ps);
  else {
    /* Default is to obey the request flags for send/recv */
    if(Curl_req_want_recv(data) && CONN_SOCK_IDX_VALID(conn->recv_idx)) {
      result = Curl_pollset_add_in(data, ps, conn->sock[conn->recv_idx]);
    }
    if(!result && Curl_req_want_send(data) &&
       CONN_SOCK_IDX_VALID(conn->send_idx)) {
      result = Curl_pollset_add_out(data, ps, conn->sock[conn->send_idx]);
    }
  }
  if(!result)
    result = multi_adjust_pollset(data, ps);
  if(!result)
    result = Curl_conn_adjust_pollset(data, conn, ps);
  return result;
}

#ifdef CURLVERBOSE
/**
 * @brief Count the entries in a transfer's timeout list.
 * @param[in] timeouts  The timeout list.
 * @return Number of nodes in the list.
 * @internal
 */
static size_t multi_timeouts_count(struct expire_timers *timeouts)
{
  size_t n = 0;
  uint8_t eid = timeouts->first;
  for(; eid < EXPIRE_LAST; eid = timeouts->next[eid])
    ++n;
  return n;
}
#endif

/**
 * @brief Initialize a pollset with the sockets a transfer waits on.
 * Initializes `ps` with the current socket poll actions needed for
 * transfer `data`, based on its state.
 * @param[in]     data  The transfer.
 * @param[in,out] ps    The pollset to (re)build.
 * @return CURLM_OK or CURLM_OUT_OF_MEMORY.
 */
CURLMcode Curl_multi_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;

  Curl_pollset_reset(ps);
#ifdef ENABLE_INTERNAL_WAKEUP
  /* The admin handle always listens on the wakeup socket when there
   * are transfers alive. */
  if(data->multi && (data == data->multi->admin) &&
     data->multi->xfers_really_alive) {
    CURL_TRC_M(data, "adding wakeup, %u xfers really alive",
               data->multi->xfers_really_alive);
    result = Curl_pollset_add_in(data, ps, data->multi->wakeup_internal[0]);
  }
#endif
  /* If the transfer has no connection, this is fine. Happens when
     called via curl_multi_remove_handle() => Curl_multi_ev_assess() =>
     Curl_multi_pollset(). */
  if(!result && data->conn) {
    switch(data->mstate) {
    case MSTATE_INIT:
    case MSTATE_PENDING:
    case MSTATE_SETUP:
    case MSTATE_CONNECT:
      /* nothing to poll for yet */
      break;

    case MSTATE_CONNECTING:
      result = mstate_connecting_pollset(data, ps);
      break;

    case MSTATE_PROTOCONNECT:
    case MSTATE_PROTOCONNECTING:
      result = mstate_protocol_pollset(data, ps);
      break;

    case MSTATE_DO:
    case MSTATE_DOING:
      result = mstate_do_pollset(data, ps);
      break;

    case MSTATE_DOING_MORE:
      result = mstate_domore_pollset(data, ps);
      break;

    case MSTATE_DID: /* same as PERFORMING in regard to polling */
    case MSTATE_PERFORMING:
      result = mstate_perform_pollset(data, ps);
      break;

    case MSTATE_RATELIMITING:
      /* we need to let time pass, ignore socket(s) */
      break;

    case MSTATE_DONE:
    case MSTATE_COMPLETED:
    case MSTATE_MSGSENT:
      /* nothing more to poll for */
      break;

    default:
      failf(data, "multi_getsock: unexpected multi state %d",
            (int)data->mstate);
      DEBUGASSERT(0);
      break;
    }
  }

  if(result) {
    if(result == CURLE_OUT_OF_MEMORY)
      return CURLM_OUT_OF_MEMORY;
    failf(data, "error determining pollset: %d", (int)result);
    return CURLM_INTERNAL_ERROR;
  }

#ifdef CURLVERBOSE
  if(CURL_TRC_M_is_verbose(data)) {
    size_t timeout_count = multi_timeouts_count(&data->state.timeouts);
    switch(ps->n) {
    case 0:
      CURL_TRC_M(data, "pollset[], timeouts=%zu, paused %d/%d (r/w)",
                 timeout_count,
                 Curl_xfer_send_is_paused(data),
                 Curl_xfer_recv_is_paused(data));
      break;
    case 1:
      CURL_TRC_M(data, "pollset[fd=%" FMT_SOCKET_T " %s%s], timeouts=%zu",
                 ps->sockets[0],
                 (ps->actions[0] & CURL_POLL_IN) ? "IN" : "",
                 (ps->actions[0] & CURL_POLL_OUT) ? "OUT" : "",
                 timeout_count);
      break;
    case 2:
      CURL_TRC_M(data, "pollset[fd=%" FMT_SOCKET_T " %s%s, "
                 "fd=%" FMT_SOCKET_T " %s%s], timeouts=%zu",
                 ps->sockets[0],
                 (ps->actions[0] & CURL_POLL_IN) ? "IN" : "",
                 (ps->actions[0] & CURL_POLL_OUT) ? "OUT" : "",
                 ps->sockets[1],
                 (ps->actions[1] & CURL_POLL_IN) ? "IN" : "",
                 (ps->actions[1] & CURL_POLL_OUT) ? "OUT" : "",
                 timeout_count);
      break;
    default:
      CURL_TRC_M(data, "pollset[fds=%u], timeouts=%zu", ps->n, timeout_count);
      break;
    }
    CURL_TRC_EASY_TIMERS(data);
  }
#endif

  return CURLM_OK;
}

/**
 * @brief Extract fd_sets for select() from a multi handle.
 * @param[in]     m            The multi handle.
 * @param[in,out] read_fd_set  Read set to add sockets to.
 * @param[in,out] write_fd_set Write set to add sockets to.
 * @param[in,out] exc_fd_set   Exception set to add sockets to.
 * @param[out]    max_fd       Highest fd added, or -1 if none.
 * @return CURLM_OK or a CURLMcode error such as CURLM_BAD_HANDLE.
 * @note Prefer curl_multi_poll() or the socket API on large fd counts.
 */
CURLMcode curl_multi_fdset(CURLM *m,
                           fd_set *read_fd_set, fd_set *write_fd_set,
                           fd_set *exc_fd_set, int *max_fd)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_fdset, &mresult)) {
    /* Scan through all the easy handles to get the file descriptors set.
       Some easy handles may not have connected to the remote host yet,
       and then we must make sure that is done. */
    struct Curl_multi *multi = m;
    struct easy_pollset ps;
    int this_max_fd = -1;
    unsigned int i;
    uint32_t mid;
    (void)exc_fd_set;

    Curl_pollset_init(&ps);
    if(Curl_uint32_bset_first(&multi->process, &mid)) {
      do {
        struct Curl_easy *data = Curl_multi_get_easy(multi, mid);

        if(!data) {
          DEBUGASSERT(0);
          continue;
        }

        Curl_multi_pollset(data, &ps);
        for(i = 0; i < ps.n; i++) {
          if(!FDSET_SOCK(ps.sockets[i]))
            /* pretend it does not exist */
            continue;
          if(ps.actions[i] & CURL_POLL_IN)
            FD_SET(ps.sockets[i], read_fd_set);
          if(ps.actions[i] & CURL_POLL_OUT)
            FD_SET(ps.sockets[i], write_fd_set);
          if((int)ps.sockets[i] > this_max_fd)
            this_max_fd = (int)ps.sockets[i];
        }
      } while(Curl_uint32_bset_next(&multi->process, mid, &mid));
    }

    Curl_cshutdn_setfds(&multi->cshutdn, multi->admin,
                        read_fd_set, write_fd_set, &this_max_fd);

    *max_fd = this_max_fd;
    Curl_pollset_cleanup(&ps);

    mresult = CURLM_OK;
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Retrieve the sockets curl waits for, as curl_waitfd array.
 * @param[in]  m         The multi handle.
 * @param[out] ufds      Array to fill (may be NULL to only count).
 * @param[in]  size      Capacity of ufds.
 * @param[out] fd_count  Number of fds needed/written (may be NULL).
 * @return CURLM_OK, CURLM_OUT_OF_MEMORY or CURLM_BAD_FUNCTION_ARGUMENT.
 */
CURLMcode curl_multi_waitfds(CURLM *m,
                             struct curl_waitfd *ufds,
                             unsigned int size,
                             unsigned int *fd_count)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_waitfds, &mresult)) {
    struct Curl_waitfds cwfds;
    struct Curl_multi *multi = m;
    struct easy_pollset ps;
    unsigned int need = 0;
    uint32_t mid;

    if(!ufds && (size || !fd_count)) {
      mresult = CURLM_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    Curl_pollset_init(&ps);
    Curl_waitfds_init(&cwfds, ufds, size);
    mresult = CURLM_OK;
    if(Curl_uint32_bset_first(&multi->process, &mid)) {
      do {
        struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
        if(!data) {
          DEBUGASSERT(0);
          Curl_uint32_bset_remove(&multi->process, mid);
          Curl_uint32_bset_remove(&multi->dirty, mid);
          continue;
        }
        Curl_multi_pollset(data, &ps);
        need += Curl_waitfds_add_ps(&cwfds, &ps);
      } while(Curl_uint32_bset_next(&multi->process, mid, &mid));
    }

    need += Curl_cshutdn_add_waitfds(&multi->cshutdn, multi->admin, &cwfds);

    if(need != cwfds.n && ufds)
      mresult = CURLM_OUT_OF_MEMORY;

    if(fd_count)
      *fd_count = need;
    Curl_pollset_cleanup(&ps);
  }
out:
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

#ifdef USE_WINSOCK
/**
 * @brief Reset FD_WRITE for TCP sockets (Windows). Nothing is sent.
 * UDP sockets cannot be reset this way because an empty datagram would
 * be sent. See #9203.
 *
 * "On Windows the internal state of FD_WRITE as returned from
 * WSAEnumNetworkEvents is only reset after successful send()."
 * @param[in] s  The socket to reset.
 * @internal
 */
static void reset_socket_fdwrite(curl_socket_t s)
{
  int t;
  int l = (int)sizeof(t);
  if(!getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&t, &l) && t == SOCK_STREAM)
    swrite(s, NULL, 0);
}

/**
 * @brief Wait for socket activity using select() on Windows.
 * @param[in,out] multi         The multi handle.
 * @param[in]     cpfds         The curl sockets to wait on.
 * @param[in]     curl_nfds     Number of curl sockets.
 * @param[in,out] extra_fds     Application supplied extra fds.
 * @param[in]     extra_nfds    Number of extra fds.
 * @param[in]     timeout_ms    Maximum wait time in milliseconds.
 * @param[in]     extrawait     Wait even if there is no socket.
 * @param[out]    pnevents      Number of events that occurred.
 * @return CURLM_OK, or CURLM_OUT_OF_MEMORY / CURLM_WAKEUP_FAILURE.
 * @internal
 */
static CURLMcode multi_winsock_select(struct Curl_multi *multi,
                                      struct curl_pollfds *cpfds,
                                      unsigned int curl_nfds,
                                      struct curl_waitfd extra_fds[],
                                      unsigned int extra_nfds,
                                      int timeout_ms,
                                      bool extrawait,
                                      int *pnevents)
{
  CURLMcode mresult = CURLM_OK;
  WSANETWORKEVENTS wsa_events;
  int nevents = 0;
  size_t i;

  DEBUGASSERT(multi->wsa_event != WSA_INVALID_EVENT);

  /* Set the WSA events based on the collected pollds */
  for(i = 0; i < cpfds->n; i++) {
    long mask = 0;
    if(cpfds->pfds[i].events & POLLIN)
      mask |= FD_READ | FD_ACCEPT | FD_CLOSE;
    if(cpfds->pfds[i].events & POLLPRI)
      mask |= FD_OOB;
    if(cpfds->pfds[i].events & POLLOUT) {
      mask |= FD_WRITE | FD_CONNECT | FD_CLOSE;
      reset_socket_fdwrite(cpfds->pfds[i].fd);
    }
    if(mask && WSAEventSelect(cpfds->pfds[i].fd, multi->wsa_event, mask)) {
      mresult = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(cpfds->n || extrawait) {
    int pollrc = 0;

    if(cpfds->n) {         /* pre-check with Winsock */
      pollrc = Curl_poll(cpfds->pfds, cpfds->n, 0);
      if(pollrc < 0) {
        mresult = CURLM_UNRECOVERABLE_POLL;
        goto out;
      }
      nevents = pollrc;
    }

    if(!nevents) {
      /* now wait... if not ready during the pre-check (pollrc == 0) */
      WSAWaitForMultipleEvents(1, &multi->wsa_event, FALSE, (DWORD)timeout_ms,
                               FALSE);
    }

    /* With Winsock, we have to run the following section unconditionally
       to call WSAEventSelect(fd, event, 0) on all the sockets */
    /* copy revents results from the poll to the curl_multi_wait poll
       struct, the bit values of the actual underlying poll() implementation
       may not be the same as the ones in the public libcurl API! */
    for(i = 0; i < extra_nfds; i++) {
      unsigned short mask = 0;
      curl_socket_t s = extra_fds[i].fd;

      wsa_events.lNetworkEvents = 0;
      if(WSAEnumNetworkEvents(s, NULL, &wsa_events) == 0) {
        if(wsa_events.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))
          mask |= CURL_WAIT_POLLIN;
        if(wsa_events.lNetworkEvents & (FD_WRITE | FD_CONNECT | FD_CLOSE))
          mask |= CURL_WAIT_POLLOUT;
        if(wsa_events.lNetworkEvents & FD_OOB)
          mask |= CURL_WAIT_POLLPRI;
        if(!pollrc && wsa_events.lNetworkEvents)
          nevents++;
      }
      WSAEventSelect(s, multi->wsa_event, 0);
      if(!pollrc) {
        extra_fds[i].revents = (short)mask;
        continue;
      }
      else {
        unsigned r = (unsigned)cpfds->pfds[curl_nfds + i].revents;
        if(r & POLLIN)
          mask |= CURL_WAIT_POLLIN;
        if(r & POLLOUT)
          mask |= CURL_WAIT_POLLOUT;
        if(r & POLLPRI)
          mask |= CURL_WAIT_POLLPRI;
        extra_fds[i].revents = (short)mask;
      }
    }

    /* Count up all our own sockets that had activity,
       and remove them from the event. */
    for(i = 0; i < curl_nfds; ++i) {
      wsa_events.lNetworkEvents = 0;
      if(WSAEnumNetworkEvents(cpfds->pfds[i].fd, NULL, &wsa_events) == 0) {
        if(!pollrc && wsa_events.lNetworkEvents)
          nevents++;
      }
      WSAEventSelect(cpfds->pfds[i].fd, multi->wsa_event, 0);
    }
    WSAResetEvent(multi->wsa_event);
  }

out:
  *pnevents = nevents;
  return mresult;
}

#else /* USE_WINSOCK */

/**
 * @brief Wait for socket activity using poll() (or select fallback).
 * @param[in,out] multi         The multi handle.
 * @param[in]     cpfds         The curl sockets to wait on.
 * @param[in]     curl_nfds     Number of curl sockets.
 * @param[in,out] extra_fds     Application supplied extra fds.
 * @param[in]     extra_nfds    Number of extra fds.
 * @param[in]     timeout_ms    Maximum wait time in milliseconds.
 * @param[in]     extrawait     Wait even if there is no socket.
 * @param[out]    pnevents      Number of events that occurred.
 * @return CURLM_OK, or CURLM_OUT_OF_MEMORY / CURLM_WAKEUP_FAILURE.
 * @internal
 */
static CURLMcode multi_posix_poll(struct Curl_multi *multi,
                                  struct curl_pollfds *cpfds,
                                  unsigned int curl_nfds,
                                  struct curl_waitfd extra_fds[],
                                  unsigned int extra_nfds,
                                  int timeout_ms,
                                  bool extrawait,
                                  int *pnevents)
{
  CURLMcode mresult = CURLM_OK;
  int nevents = 0;
  size_t i;

  (void)multi;
  if(cpfds->n) {
    int pollrc = Curl_poll(cpfds->pfds, cpfds->n, timeout_ms); /* wait... */
    if(pollrc < 0) {
      mresult = CURLM_UNRECOVERABLE_POLL;
      goto out;
    }
    nevents = pollrc;

    /* copy revents results from the poll to the curl_multi_wait poll
       struct, the bit values of the actual underlying poll() implementation
       may not be the same as the ones in the public libcurl API! */
    for(i = 0; i < extra_nfds; i++) {
      unsigned r = (unsigned)cpfds->pfds[curl_nfds + i].revents;
      unsigned short mask = 0;
      if(r & POLLIN)
        mask |= CURL_WAIT_POLLIN;
      if(r & POLLOUT)
        mask |= CURL_WAIT_POLLOUT;
      if(r & POLLPRI)
        mask |= CURL_WAIT_POLLPRI;
      extra_fds[i].revents = (short)mask;
    }
  }
  else if(extrawait) {
    /* No fds to poll, but asked to obey timeout_ms anyway. We cannot
     * use Curl_poll() as it, on some platforms, returns immediately
     * without fds. */
    curlx_wait_ms(timeout_ms);
  }

out:
  *pnevents = nevents;
  return mresult;
}

#endif /* !USE_WINSOCK */

/**
 * @def NUM_POLLS_ON_STACK
 * @brief Number of pollfd entries kept on the stack in multi_wait().
 */
#define NUM_POLLS_ON_STACK 10

/**
 * @brief Common implementation of curl_multi_wait() and _poll().
 * Collects the sockets of all transfers, adds the application's extra fds
 * and optionally the wakeup fd, then waits for activity or timeout.
 * @param[in,out] multi       The multi handle.
 * @param[in,out] extra_fds   Extra fds supplied by the application.
 * @param[in]     extra_nfds  Number of extra fds.
 * @param[in]     timeout_ms  Maximum wait time in milliseconds.
 * @param[out]    ret         Number of events (may be NULL).
 * @param[in]     extrawait   When no socket exists, still wait.
 * @return CURLM_OK, CURLM_BAD_FUNCTION_ARGUMENT, CURLM_OUT_OF_MEMORY or
 *         CURLM_WAKEUP_FAILURE.
 * @internal
 */
static CURLMcode multi_wait(struct Curl_multi *multi,
                            struct curl_waitfd extra_fds[],
                            unsigned int extra_nfds,
                            int timeout_ms,
                            int *ret,
                            bool extrawait)  /* when no socket, wait */
{
  size_t i;
  int timeout_internal;
  int nevents = 0;
  struct easy_pollset ps;
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct curl_pollfds cpfds;
  unsigned int curl_nfds = 0; /* how many pfds are for curl transfers */
  struct Curl_easy *data = NULL;
  CURLMcode mresult = CURLM_OK;
  uint32_t mid;
#ifdef ENABLE_WAKEUP
  int wakeup_idx = -1;
#endif

  if(timeout_ms < 0)
    return CURLM_BAD_FUNCTION_ARGUMENT;

  Curl_pollset_init(&ps);
  Curl_pollfds_init(&cpfds, a_few_on_stack, NUM_POLLS_ON_STACK);

  /* Add the curl handles to our pollfds first */
  if(Curl_uint32_bset_first(&multi->process, &mid)) {
    do {
      data = Curl_multi_get_easy(multi, mid);
      if(!data) {
        DEBUGASSERT(0);
        Curl_uint32_bset_remove(&multi->process, mid);
        Curl_uint32_bset_remove(&multi->dirty, mid);
        continue;
      }
      Curl_multi_pollset(data, &ps);
      if(Curl_pollfds_add_ps(&cpfds, &ps)) {
        mresult = CURLM_OUT_OF_MEMORY;
        goto out;
      }
    } while(Curl_uint32_bset_next(&multi->process, mid, &mid));
  }

  if(Curl_cshutdn_add_pollfds(&multi->cshutdn, multi->admin, &cpfds)) {
    mresult = CURLM_OUT_OF_MEMORY;
    goto out;
  }

#ifdef ENABLE_WAKEUP
  /* If `extrawait` is TRUE *or* we have `extra_fds`to poll *or* we
   * have transfer sockets to poll, we obey `timeout_ms`.
   * Then we need to also monitor the multi's wakeup
   * socket to catch calls to `curl_multi_wakeup()` during the wait. */
  if(extrawait || cpfds.n || extra_nfds) {
    wakeup_idx = cpfds.n;
    if(Curl_pollfds_add_sock(&cpfds, multi->wakeup_pair[0], POLLIN)) {
      mresult = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }
#endif

  curl_nfds = cpfds.n; /* what curl internally uses in cpfds */
  /* Add external file descriptions from poll-like struct curl_waitfd */
  for(i = 0; i < extra_nfds; i++) {
    unsigned short events = 0;
    if(extra_fds[i].events & CURL_WAIT_POLLIN)
      events |= POLLIN;
    if(extra_fds[i].events & CURL_WAIT_POLLPRI)
      events |= POLLPRI;
    if(extra_fds[i].events & CURL_WAIT_POLLOUT)
      events |= POLLOUT;
    if(Curl_pollfds_add_sock(&cpfds, extra_fds[i].fd, events)) {
      mresult = CURLM_OUT_OF_MEMORY;
      goto out;
    }
  }

  /* We check the internal timeout *AFTER* we collected all sockets to
   * poll. Collecting the sockets may install new timers by protocols
   * and connection filters.
   * Use the shorter one of the internal and the caller requested timeout.
   * If we are called with `!extrawait` and multi_timeout() reports no
   * timeouts exist, do not wait. */
  multi_timeout(multi, NULL, &timeout_internal);
  if((timeout_internal >= 0) && (timeout_internal < timeout_ms))
    timeout_ms = timeout_internal;

  if(data)
    CURL_TRC_M(data, "multi_wait(fds=%u, timeout=%d) tinternal=%d",
               cpfds.n, timeout_ms, timeout_internal);

#ifdef USE_WINSOCK
  mresult = multi_winsock_select(multi, &cpfds, curl_nfds,
                                 extra_fds, extra_nfds,
                                 timeout_ms, extrawait, &nevents);
#else
  mresult = multi_posix_poll(multi, &cpfds, curl_nfds,
                             extra_fds, extra_nfds,
                             timeout_ms, extrawait, &nevents);
#endif

#ifdef ENABLE_WAKEUP
    if(nevents && (wakeup_idx >= 0)) {
      if(cpfds.pfds[wakeup_idx].revents & POLLIN) {
        (void)Curl_wakeup_consume(multi->wakeup_pair, TRUE);
        /* do not count the wakeup socket into the returned value */
        nevents--;
      }
    }
#endif

out:
  Curl_pollset_cleanup(&ps);
  Curl_pollfds_cleanup(&cpfds);
  if(ret)
    *ret = nevents;
  return mresult;
}

/**
 * @brief Wait for activity on curl's or extra sockets (public API).
 * @param[in]     m           The multi handle.
 * @param[in,out] extra_fds   Extra fds to wait on (may be NULL).
 * @param[in]     extra_nfds  Number of extra fds.
 * @param[in]     timeout_ms  Maximum wait time in milliseconds.
 * @param[out]    ret         Number of fds with events (may be NULL).
 * @return CURLM_OK or a CURLMcode error.
 * @note Returns immediately if there is nothing to wait for.
 * @see curl_multi_poll()
 */
CURLMcode curl_multi_wait(CURLM *m,
                          struct curl_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *ret)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_wait, &mresult)) {
    mresult = multi_wait(m, extra_fds, extra_nfds, timeout_ms, ret, FALSE);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Like curl_multi_wait() but waits even without sockets.
 * Can be interrupted by curl_multi_wakeup().
 * @param[in]     m           The multi handle.
 * @param[in,out] extra_fds   Extra fds to wait on (may be NULL).
 * @param[in]     extra_nfds  Number of extra fds.
 * @param[in]     timeout_ms  Maximum wait time in milliseconds.
 * @param[out]    ret         Number of fds with events (may be NULL).
 * @return CURLM_OK or a CURLMcode error.
 * @see curl_multi_wakeup()
 */
CURLMcode curl_multi_poll(CURLM *m,
                          struct curl_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *ret)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_poll, &mresult)) {
    mresult = multi_wait(m, extra_fds, extra_nfds, timeout_ms, ret, TRUE);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Wake up a thread blocked in curl_multi_poll().
 * @param[in] m  The multi handle.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_WAKEUP_FAILURE.
 * @note This is the only multi function that is safe to call from
 * another thread while the multi handle is in use.
 */
CURLMcode curl_multi_wakeup(CURLM *m)
{
  /* this function is usually called from another thread,
     it has to be careful only to access parts of the
     Curl_multi struct that are constant */
  struct Curl_multi *multi = m;
  CURLMcode mresult = CURLM_WAKEUP_FAILURE;

  /* GOOD_MULTI_HANDLE can be safely called */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

#ifdef ENABLE_WAKEUP
  /* the wakeup_pair variable is only written during init and cleanup,
     making it safe to access from another thread after the init part
     and before cleanup */
  if(!Curl_wakeup_signal(multi->wakeup_pair))
    mresult = CURLM_OK;
#endif
#ifdef USE_WINSOCK
  if(WSASetEvent(multi->wsa_event))
    mresult = CURLM_OK;
#endif
  return mresult;
}

#ifdef ENABLE_INTERNAL_WAKEUP
/**
 * @brief Trigger the multi wakeup mechanism from inside libcurl.
 * Compiled only when ENABLE_INTERNAL_WAKEUP is set.
 * @param[in] multi  The multi handle.
 */
void Curl_multi_wakeup_internal(struct Curl_multi *multi)
{
  /* This is expected to be invocable from another thread which
   * does NOT outlive the multi handle. Check for sanity. */
  if(GOOD_MULTI_HANDLE(multi))
    Curl_wakeup_signal(multi->wakeup_internal);
  else
    DEBUGASSERT(0);
}
#endif

/**
 * @brief Check whether CONNECT_PEND transfers should be retried.
 * Returns TRUE/FALSE whether the state is changed to trigger a
 * CONNECT_PEND => CONNECT action.
 * @param[in,out] multi  The multi handle.
 * @param[in]     clear  Set to TRUE to also clear the state variable.
 * @return TRUE if the state had changed.
 * @internal
 */
static bool multi_ischanged(struct Curl_multi *multi, bool clear)
{
  bool retval = FALSE;
  DEBUGASSERT(multi);
  if(multi) {
    retval = (bool)multi->recheckstate;
    if(clear)
      multi->recheckstate = FALSE;
  }
  return retval;
}

/**
 * @brief Tell the multi that a connection changed state.
 * Multiplexing became possible, the number of allowed streams changed or
 * similar. A subsequent use of this multi handle then moves CONNECT_PEND
 * handles back to CONNECT to have them retry.
 * @param[in,out] multi  The multi handle.
 */
void Curl_multi_connchanged(struct Curl_multi *multi)
{
  /* May be invoked for a `data->multi` when no multi is present. */
  if(multi)
    multi->recheckstate = TRUE;
}

/**
 * @brief Add a transfer and run it using an existing connection.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer to add.
 * @param[in,out] conn   The connection to attach to the transfer.
 * @return CURLM_OK or a CURLMcode error from adding/performing.
 */
CURLMcode Curl_multi_add_perform(struct Curl_multi *multi,
                                 struct Curl_easy *data,
                                 struct connectdata *conn)
{
  CURLMcode mresult;

  mresult = Curl_multi_add_handle(multi, data);
  if(!mresult) {
    CURLcode result;

    /* pass in NULL for 'conn' here since we do not want to init the
       connection, only this transfer */
    result = Curl_init_transfer(data, NULL);
    if(result) {
      Curl_multi_remove_handle(multi, data);
      return CURLM_INTERNAL_ERROR;
    }

    /* take this handle to the perform state right away */
    multistate(data, MSTATE_PERFORMING);
    Curl_attach_connection(data, conn, TRUE);
    CURL_REQ_SET_RECV(data);
  }
  return mresult;
}

/**
 * @brief Run the protocol "do" action (send the request).
 * @param[in,out] data  The transfer.
 * @param[out]    done  TRUE when the do phase is complete.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode multi_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->scheme);

  if(conn->scheme->run->do_it)
    result = conn->scheme->run->do_it(data, done);

  return result;
}

/*
 * multi_do_more() is called during the DO_MORE multi state. It is a second
 * stage DO state which (wrongly) was introduced to support FTP's second
 * connection.
 *
 * 'complete' can return DOMORE_INCOMPLETE, DOMORE_DONE or DOMORE_GOBACK
 * (to DOING state when there is more work to do)
 */

/**
 * @brief Run the protocol "do more" action.
 * @param[in,out] data      The transfer.
 * @param[out]    complete  Whether the do-more phase finished.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode multi_do_more(struct Curl_easy *data, domore *complete)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  *complete = DOMORE_INCOMPLETE;

  if(conn->scheme->run->do_more)
    result = conn->scheme->run->do_more(data, complete);

  return result;
}

/**
 * @brief Check whether a timeout occurred, and handle it if it did.
 * On timeout, the retry logic may decide to try again.
 * @param[in,out] data           The transfer.
 * @param[in]     pnow           Current time.
 * @param[out]    stream_error   Set TRUE if only the stream failed.
 * @param[out]    result         Error to report on timeout.
 * @return TRUE if a timeout was handled (result is then set), FALSE
 *         if no timeout happened.
 * @internal
 */
static bool multi_handle_timeout(struct Curl_easy *data,
                                 const struct curltime *pnow,
                                 bool *stream_error,
                                 CURLcode *result)
{
  timediff_t timeout_ms;

  timeout_ms = Curl_timeleft_now_ms(data, pnow);
  if(timeout_ms < 0) {
    /* Handle timed out */
    timerid base_timer = Curl_is_connecting(data) ?
                         TIMER_STARTSINGLE : TIMER_STARTOP;
    timediff_t elapsed_ms = Curl_pgrs_since_ms(data, NULL, base_timer);
    if(data->mstate == MSTATE_CONNECTING) {
      failf(data, "%s timed out after %" FMT_TIMEDIFF_T " milliseconds",
            data->conn->bits.dns_resolved ? "Connection" : "Resolving",
            elapsed_ms);
      /* keep what we know about a partly done connect, e.g. TCP done
       * but TLS handshake still ongoing */
      Curl_conn_report_failed(data, FIRSTSOCKET);
    }
    else {
      struct SingleRequest *k = &data->req;
      if(k->size != -1) {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " out of %"
              FMT_OFF_T " bytes received",
              elapsed_ms, k->bytecount, k->size);
      }
      else {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " bytes received",
              elapsed_ms, k->bytecount);
      }
    }
    *result = CURLE_OPERATION_TIMEDOUT;
    if(data->conn) {
      /* Force connection closed if the connection has indeed been used */
      if(data->mstate > MSTATE_DO) {
        streamclose(data->conn);
        *stream_error = TRUE;
      }
      (void)multi_done(data, *result, TRUE);
    }
    return TRUE;
  }

  return FALSE;
}

/*
 * We are doing protocol-specific connecting and this is being called over and
 * over from the multi interface until the connection phase is done on
 * protocol layer.
 */

/**
 * @brief Continue a non-blocking protocol connect phase.
 * @param[in,out] data  The transfer.
 * @param[out]    done  TRUE when the protocol connect is finished.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode protocol_connecting(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(conn && conn->scheme->run->connecting) {
    *done = FALSE;
    result = conn->scheme->run->connecting(data, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We are DOING this is being called over and over from the multi interface
 * until the DOING phase is done on protocol layer.
 */

/**
 * @brief Continue a non-blocking protocol "doing" phase.
 * @param[in,out] data  The transfer.
 * @param[out]    done  TRUE when the doing phase is finished.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode protocol_doing(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn = data->conn;

  if(conn && conn->scheme->run->doing) {
    *done = FALSE;
    result = conn->scheme->run->doing(data, done);
  }
  else
    *done = TRUE;

  return result;
}

/**
 * @brief Proceed after the TCP connection succeeded.
 * We have discovered that the TCP connection has been successful, we can
 * now proceed with some action: start the protocol connect, if any.
 * @param[in,out] data           The transfer.
 * @param[out]    protocol_done  TRUE if no further protocol connect
 *                               is needed.
 * @return CURLE_OK or an error from the protocol handler.
 * @internal
 */
static CURLcode protocol_connect(struct Curl_easy *data, bool *protocol_done)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(conn);
  DEBUGASSERT(protocol_done);
  DEBUGASSERT(Curl_conn_is_connected(conn, FIRSTSOCKET));

  *protocol_done = FALSE;
  if(!conn->bits.protoconnstart) {
    if(conn->scheme->run->connect_it) {
      /* Call the protocol-specific connect function */
      result = conn->scheme->run->connect_it(data, protocol_done);
      if(result)
        return result;
    }
    conn->bits.protoconnstart = TRUE;
  }

  /* Unless this protocol does not have any protocol-connect callback, as
     then we know we are done. */
  if(!conn->scheme->run->connecting)
    *protocol_done = TRUE;
  return CURLE_OK;
}

/**
 * @brief Called immediately after a transfer ends.
 * Restores the SIGPIPE handling and similar per-transfer state.
 * @param[in,out] data  The transfer.
 * @internal
 */
static void multi_posttransfer(struct Curl_easy *data)
{
#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(MSG_NOSIGNAL)
  /* restore the signal handler for SIGPIPE before we get back */
  if(!data->set.no_signal)
    signal(SIGPIPE, data->state.prev_signal);
#else
  (void)data;
#endif
}

/**
 * @brief Handle URL redirect magic.
 * Pass in the 'newurl' string as given by the remote server and set up
 * the new URL to request.
 * @param[in,out] data     The transfer.
 * @param[in]     handler  The scheme handler of the current URL.
 * @param[in]     newurl   The Location: string.
 * @param[in]     type     Kind of follow, see transfer.h.
 * @return CURLE_OK, CURLE_TOO_MANY_REDIRECTS, CURLE_OUT_OF_MEMORY or
 *         another redirect error.
 * @warning This function DOES NOT FREE the given URL.
 * @internal
 */
static CURLcode multi_follow(struct Curl_easy *data,
                             const struct Curl_scheme *handler,
                             const char *newurl, /* the Location: string */
                             followtype type) /* see transfer.h */
{
  if(handler && handler->run->follow)
    return handler->run->follow(data, newurl, type);

  if(type == FOLLOW_RETRY)
    /* Retries are generic and do not require protocol-specific redirect
       handling. */
    return CURLE_OK;

  return CURLE_TOO_MANY_REDIRECTS;
}

/**
 * @brief Check transfer speed against rate limits.
 * Applies CURLOPT_MAX_*_SPEED_LIMIT and low speed (abort) limits.
 * @param[in,out] data  The transfer.
 * @return CURLE_OK, or CURLE_OPERATION_TIMEDOUT if the transfer was too
 *         slow for too long.
 * @internal
 */
static CURLcode mspeed_check(struct Curl_easy *data)
{
  if(Curl_rlimit_active(&data->progress.dl.rlimit) ||
     Curl_rlimit_active(&data->progress.ul.rlimit)) {
    /* check if our send/recv limits require idle waits */
    const struct curltime *pnow = Curl_pgrs_now(data);
    timediff_t recv_ms, send_ms;

    send_ms = Curl_rlimit_wait_ms(&data->progress.ul.rlimit, pnow);
    recv_ms = Curl_rlimit_wait_ms(&data->progress.dl.rlimit, pnow);

    if(send_ms || recv_ms) {
      if(data->mstate != MSTATE_RATELIMITING) {
        multistate(data, MSTATE_RATELIMITING);
      }
      Curl_expire_set(data, EXPIRE_TOOFAST, CURLMAX(send_ms, recv_ms), pnow);
      Curl_multi_clear_dirty(data);
      CURL_TRC_M(data, "[RLIMIT] waiting %" FMT_TIMEDIFF_T "ms",
                 CURLMAX(send_ms, recv_ms));
      return CURLE_AGAIN;
    }
    else {
      /* when will the rate limits increase next? The transfer needs
       * to run again at that time or it may stall. */
      send_ms = Curl_rlimit_next_step_ms(&data->progress.ul.rlimit, pnow);
      recv_ms = Curl_rlimit_next_step_ms(&data->progress.dl.rlimit, pnow);
      if(send_ms || recv_ms) {
        timediff_t next_ms = CURLMIN(send_ms, recv_ms);
        if(!next_ms)
          next_ms = CURLMAX(send_ms, recv_ms);
        Curl_expire_set(data, EXPIRE_TOOFAST, next_ms, pnow);
        CURL_TRC_M(data, "[RLIMIT] next token update in %" FMT_TIMEDIFF_T "ms",
                   next_ms);
      }
    }
  }

  if(data->mstate != MSTATE_PERFORMING) {
    CURL_TRC_M(data, "[RLIMIT] wait over, continue");
    multistate(data, MSTATE_PERFORMING);
  }
  return CURLE_OK;
}

/**
 * @brief State handler for MSTATE_PERFORMING.
 * Moves data, checks speed limits and decides whether to continue,
 * finish or retry.
 * @param[in,out] data           The transfer.
 * @param[out]    stream_errorp  Set TRUE on a stream-only failure.
 * @param[out]    resultp        Transfer result on error/completion.
 * @return CURLM_OK, or CURLM_CALL_MULTI_PERFORM when the state changed
 *         and should be run again.
 * @internal
 */
static CURLMcode multistate_performing(struct Curl_easy *data,
                                       bool *stream_errorp,
                                       CURLcode *resultp)
{
  char *newurl = NULL;
  bool retry = FALSE;
  CURLMcode mresult = CURLM_OK;
  CURLcode result = *resultp = CURLE_OK;
  *stream_errorp = FALSE;

  if(mspeed_check(data) == CURLE_AGAIN)
    return CURLM_OK;

  /* read/write data if it is ready to do so */
  result = Curl_sendrecv(data);

  if(data->req.done || (result == CURLE_RECV_ERROR)) {
    /* If CURLE_RECV_ERROR happens early enough, we assume it was a race
     * condition and the server closed the reused connection exactly when we
     * wanted to use it, so figure out if that is indeed the case.
     */
    CURLcode ret = Curl_retry_request(data, &newurl);
    if(!ret)
      retry = !!newurl;
    else if(!result)
      result = ret;

    if(retry) {
      /* if we are to retry, set the result to OK and consider the
         request as done */
      result = CURLE_OK;
      data->req.done = TRUE;
    }
  }
#ifndef CURL_DISABLE_HTTP
  else if((result == CURLE_HTTP2_STREAM) &&
          Curl_h2_http_1_1_error(data)) {
    CURLcode ret = Curl_retry_request(data, &newurl);

    if(!ret) {
      infof(data, "Downgrades to HTTP/1.1");
      streamclose(data->conn);
      data->state.http_neg.wanted = CURL_HTTP_V1x;
      data->state.http_neg.allowed = CURL_HTTP_V1x;
      /* clear the error message bit too as we ignore the one we got */
      data->state.errorbuf = FALSE;
      if(!newurl)
        /* typically for HTTP_1_1_REQUIRED error on first flight */
        newurl = Curl_bufref_dup(&data->state.url);
      if(!newurl) {
        result = CURLE_OUT_OF_MEMORY;
      }
      else {
        /* if we are to retry, set the result to OK and consider the request
          as done */
        retry = TRUE;
        result = CURLE_OK;
        data->req.done = TRUE;
      }
    }
    else
      result = ret;
  }
#endif

  if(result) {
    /*
     * The transfer phase returned error, we mark the connection to get closed
     * to prevent being reused. This is because we cannot possibly know if the
     * connection is in a good shape or not now. Unless it is a protocol which
     * uses two "channels" like FTP, as then the error happened in the data
     * connection.
     */

    if(!(data->conn->scheme->flags & PROTOPT_DUAL) &&
       result != CURLE_HTTP2_STREAM)
      streamclose(data->conn);

    multi_posttransfer(data);
    multi_done(data, result, TRUE);
  }
  else if(data->req.done && !Curl_cwriter_is_paused(data)) {
    const struct Curl_scheme *handler = data->conn->scheme;

    /* call this even if the readwrite function returned error */
    multi_posttransfer(data);

    /* When we follow redirects or is set to retry the connection, we must to
       go back to the CONNECT state */
    if(data->req.newurl || retry) {
      followtype follow = FOLLOW_NONE;
      if(!retry) {
        /* if the URL is a follow-location and not a retried request then
           figure out the URL here */
        curlx_free(newurl);
        newurl = data->req.newurl;
        data->req.newurl = NULL;
        follow = FOLLOW_REDIR;
      }
      else
        follow = FOLLOW_RETRY;
      (void)multi_done(data, CURLE_OK, FALSE);
      /* multi_done() might return CURLE_GOT_NOTHING */
      result = multi_follow(data, handler, newurl, follow);
      if(!result) {
        multistate(data, MSTATE_SETUP);
        mresult = CURLM_CALL_MULTI_PERFORM;
      }
    }
    else {
      /* after the transfer is done, go DONE */

      /* but first check to see if we got a location info even though we are
         not following redirects */
      if(data->req.location) {
        curlx_free(newurl);
        newurl = data->req.location;
        data->req.location = NULL;
        result = multi_follow(data, handler, newurl, FOLLOW_FAKE);
        if(result) {
          *stream_errorp = TRUE;
          result = multi_done(data, result, TRUE);
        }
      }

      if(!result) {
        multistate(data, MSTATE_DONE);
        mresult = CURLM_CALL_MULTI_PERFORM;
      }
    }
  }
  else { /* not errored, not done */
    mspeed_check(data);
  }
  curlx_free(newurl);
  *resultp = result;
  return mresult;
}

/**
 * @brief State handler for MSTATE_DO.
 * Starts the protocol "do" action and moves on to DOING, DOING_MORE,
 * DID or back to CONNECT on retry.
 * @param[in,out] data           The transfer.
 * @param[out]    stream_errorp  Set TRUE on a stream-only failure.
 * @param[out]    resultp        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_do(struct Curl_easy *data,
                               bool *stream_errorp,
                               CURLcode *resultp)
{
  CURLMcode mresult = CURLM_OK;
  CURLcode result = CURLE_OK;
  if(data->set.fprereq) {
    struct Curl_mapi_guard guard;
    int prereq_rc;

    /* call the prerequest callback function */
    CURL_CBAPI_START(&guard, data, easy_fprereq);
    prereq_rc = data->set.fprereq(data->set.prereq_userp,
                                  data->info.primary.remote_ip,
                                  data->info.primary.local_ip,
                                  data->info.primary.remote_port,
                                  data->info.primary.local_port);
    CURL_CBAPI_END(&guard);
    if(prereq_rc != CURL_PREREQFUNC_OK) {
      failf(data, "operation aborted by pre-request callback");
      /* failure in pre-request callback - do not do any other processing */
      result = CURLE_ABORTED_BY_CALLBACK;
      multi_posttransfer(data);
      multi_done(data, result, FALSE);
      *stream_errorp = TRUE;
      goto end;
    }
  }

  if(data->set.connect_only && !data->set.connect_only_ws) {
    multistate(data, MSTATE_DONE);
    mresult = CURLM_CALL_MULTI_PERFORM;
  }
  else {
    bool dophase_done = FALSE;
    /* Perform the protocol's DO action */
    result = multi_do(data, &dophase_done);

    if(!result) {
      if(!dophase_done) {
#ifndef CURL_DISABLE_FTP
        /* some steps needed for wildcard matching */
        if(data->state.wildcardmatch) {
          struct WildcardData *wc = data->wildcard;
          if(wc->state == CURLWC_DONE || wc->state == CURLWC_SKIP) {
            /* skip some states if it is important */
            multi_done(data, CURLE_OK, FALSE);

            /* if there is no connection left, skip the DONE state */
            multistate(data, data->conn ? MSTATE_DONE : MSTATE_COMPLETED);
            mresult = CURLM_CALL_MULTI_PERFORM;
            goto end;
          }
        }
#endif
        /* DO was not completed in one function call, we must continue
           DOING... */
        multistate(data, MSTATE_DOING);
        mresult = CURLM_CALL_MULTI_PERFORM;
      }

      /* after DO, go DO_DONE... or DO_MORE */
      else if(data->conn->bits.do_more) {
        /* we are supposed to do more, but we need to sit down, relax and wait
           a little while first */
        multistate(data, MSTATE_DOING_MORE);
        mresult = CURLM_CALL_MULTI_PERFORM;
      }
      else {
        /* we are done with the DO, now DID */
        multistate(data, MSTATE_DID);
        mresult = CURLM_CALL_MULTI_PERFORM;
      }
    }
    else if((result == CURLE_SEND_ERROR) &&
            data->conn->bits.reuse) {
      /*
       * In this situation, a connection that we were trying to use may have
       * unexpectedly died. If possible, send the connection back to the
       * CONNECT phase so we can try again.
       */
      const struct Curl_scheme *handler = data->conn->scheme;
      char *newurl = NULL;
      followtype follow = FOLLOW_NONE;
      CURLcode drc;

      drc = Curl_retry_request(data, &newurl);
      if(drc) {
        /* a failure here pretty much implies an out of memory */
        result = drc;
        *stream_errorp = TRUE;
      }

      multi_posttransfer(data);
      drc = multi_done(data, result, FALSE);

      /* When set to retry the connection, we must go back to the CONNECT
       * state */
      if(newurl) {
        if(!drc || (drc == CURLE_SEND_ERROR)) {
          follow = FOLLOW_RETRY;
          drc = multi_follow(data, handler, newurl, follow);
          if(!drc) {
            multistate(data, MSTATE_SETUP);
            mresult = CURLM_CALL_MULTI_PERFORM;
            result = CURLE_OK;
          }
          else {
            /* Follow failed */
            result = drc;
          }
        }
        else {
          /* done did not return OK or SEND_ERROR */
          result = drc;
        }
      }
      else {
        /* Have error handler disconnect conn if we cannot retry */
        *stream_errorp = TRUE;
      }
      curlx_free(newurl);
    }
    else {
      /* failure detected */
      multi_posttransfer(data);
      if(data->conn)
        multi_done(data, result, FALSE);
      *stream_errorp = TRUE;
    }
  }
end:
  *resultp = result;
  return mresult;
}

/**
 * @brief State handler for MSTATE_RATELIMITING.
 * Leaves the state once the rate limit timeout has passed.
 * @param[in,out] data     The transfer.
 * @param[out]    resultp  Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_ratelimiting(struct Curl_easy *data,
                                         CURLcode *resultp)
{
  CURLcode result = CURLE_OK;
  CURLMcode mresult = CURLM_OK;
  DEBUGASSERT(data->conn);
  /* if both rates are within spec, resume transfer */
  result = Curl_pgrsCheck(data);

  if(result) {
    if(!(data->conn->scheme->flags & PROTOPT_DUAL) &&
       result != CURLE_HTTP2_STREAM)
      streamclose(data->conn);

    multi_posttransfer(data);
    multi_done(data, result, TRUE);
  }
  else {
    if(!mspeed_check(data))
      mresult = CURLM_CALL_MULTI_PERFORM;
  }
  *resultp = result;
  return mresult;
}

/**
 * @brief State handler for MSTATE_CONNECT.
 * Starts or reuses a connection, may queue the transfer as PENDING when
 * connection limits apply or when waiting for multiplexing.
 * @param[in,out] multi    The multi handle.
 * @param[in,out] data     The transfer.
 * @param[out]    resultp  Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_connect(struct Curl_multi *multi,
                                    struct Curl_easy *data,
                                    CURLcode *resultp)
{
  /* Connect. We want to get a connection identifier filled in. This state can
     be entered from SETUP and from PENDING. */
  bool connected;
  CURLMcode mresult = CURLM_OK;
  CURLcode result = Curl_connect(data, &connected);
  if(result == CURLE_NO_CONNECTION_AVAILABLE) {
    /* There was no connection available. We will go to the pending state and
       wait for an available connection. */
    multistate(data, MSTATE_PENDING);
    /* move from process to pending set */
    Curl_uint32_bset_remove(&multi->process, data->mid);
    Curl_uint32_bset_remove(&multi->dirty, data->mid);
    Curl_uint32_bset_add(&multi->pending, data->mid);
    *resultp = CURLE_OK;
    return mresult;
  }
  else
    multi_schedule_pending(data->multi);

  if(!result) {
    /* after the connect has been sent off, go WAITCONNECT unless the
       protocol connect is already done and we can go directly to WAITDO or
       DO! */
    mresult = CURLM_CALL_MULTI_PERFORM;

    if(connected) {
      if(!data->conn->bits.reuse &&
         Curl_conn_is_multiplex(data->conn, FIRSTSOCKET)) {
        /* new connection, can multiplex, wake pending handles */
        multi_schedule_pending(data->multi);
      }
      multistate(data, MSTATE_PROTOCONNECT);
    }
    else {
      multistate(data, MSTATE_CONNECTING);
    }
  }
  *resultp = result;
  return mresult;
}

/**
 * @brief Decide whether a transfer is finished after an error/result.
 * Returns the possibly updated result.
 * @param[in,out] multi         The multi handle.
 * @param[in,out] data          The transfer.
 * @param[in]     pnow          Current time.
 * @param[in]     stream_error  TRUE if only the stream failed.
 * @param[in]     result        Result of the last operation.
 * @return The possibly updated CURLcode.
 * @internal
 */
static CURLcode is_finished(struct Curl_multi *multi,
                            struct Curl_easy *data,
                            const struct curltime *pnow,
                            bool stream_error,
                            CURLcode result)
{
  if(data->mstate < MSTATE_COMPLETED) {
    if(result) {
      /*
       * If an error was returned, and we are not in completed state now,
       * then we go to completed and consider this transfer aborted.
       */

      /* No attempt to disconnect connections must be made before this -
         connection detach and termination happens only here */

      /* Check if we can move pending requests to send pipe */
      multi_schedule_pending(multi); /* connection */

      if(data->conn) {
        if(stream_error) {
          /* Do not attempt to send data over a connection that timed out */
          bool dead_connection = result == CURLE_OPERATION_TIMEDOUT;
          struct connectdata *conn = data->conn;

          /* This is where we make sure that the conn pointer is reset.
             We do not have to do this in every case block above where a
             failure is detected */
          Curl_detach_connection(data);
          Curl_conn_close(data, conn, dead_connection);
        }
      }
      else if(data->mstate == MSTATE_CONNECT) {
        /* Curl_connect() failed */
        multi_posttransfer(data);
        Curl_pgrsUpdate_nometer(data);
      }

      multistate(data, MSTATE_COMPLETED);
      return result;
    }
    /* if there is still a connection to use, call the progress function */
    else if(data->conn && Curl_conn_is_connected(data->conn, FIRSTSOCKET)) {
      result = Curl_pgrsUpdateX(data, pnow);
      if(result) {
        /* aborted due to progress callback return code must close the
           connection */
        streamclose(data->conn);

        /* if not yet in DONE state, go there. */
        if(data->mstate < MSTATE_DONE)
          multistate(data, MSTATE_DONE);
        return result;
      }
    }
  }
  return result;
}

/**
 * @brief Move a finished transfer to COMPLETED and queue its message.
 * @param[in,out] multi   The multi handle.
 * @param[in,out] data    The finished transfer.
 * @param[in]     result  Final result reported to the application.
 * @internal
 */
static void handle_completed(struct Curl_multi *multi,
                             struct Curl_easy *data,
                             CURLcode result)
{
  bool msg_to_app = data->master_mid == UINT32_MAX;

  if(!msg_to_app) {
    /* A sub transfer, not reported to the application. Is anyone still
     * interested in processing its results? */
    if(data->sub_xfer_done) {
      struct Curl_easy *master = Curl_multi_get_easy(multi, data->master_mid);

      CURL_TRC_M(data, "sub xfer done for master %u", data->master_mid);
      if(master)
        data->sub_xfer_done(data, master, result);
      else
        CURL_TRC_M(data, "master easy %u already gone.", data->master_mid);
    }
  }
  else {
    /* now fill in the CURLMsg with this info */
    struct CURLMsg *msg = &data->msg;

    msg->msg = CURLMSG_DONE;
    msg->easy_handle = data;
    msg->data.result = result;

    DEBUGASSERT(!data->conn);
  }
  multistate(data, MSTATE_MSGSENT);

  /* remove from the other sets */
  Curl_uint32_bset_remove(&multi->process, data->mid);
  Curl_uint32_bset_remove(&multi->dirty, data->mid);
  Curl_uint32_bset_remove(&multi->pending, data->mid);
  if(msg_to_app)
    multi_addmsg(multi, data);
  if(data->state.really_alive) {
    data->state.really_alive = FALSE;
    --multi->xfers_really_alive;
    if(!multi->xfers_really_alive)
      (void)multi_assess_wakeup(multi);
  }
  --multi->xfers_alive;
  if(!multi->xfers_alive)
    multi_assess_wakeup(multi);
}

/**
 * @brief State handler for MSTATE_INIT.
 * @param[in,out] data    The transfer.
 * @param[out]    result  Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_init(struct Curl_easy *data, CURLcode *result)
{
  if(!data->state.really_alive) {
    data->state.really_alive = TRUE;
    ++data->multi->xfers_really_alive;
    if(data->multi->xfers_really_alive == 1) {
      CURLMcode mresult = multi_assess_wakeup(data->multi);
      if(mresult) {
        failf(data, "error enabling wakeup listening: %d", mresult);
        return mresult;
      }
    }
  }

  *result = Curl_pretransfer(data);
  if(*result)
    return CURLM_OK;

  /* after init, go SETUP */
  multistate(data, MSTATE_SETUP);
  Curl_pgrsTime(data, TIMER_STARTOP);
  return CURLM_CALL_MULTI_PERFORM;
}

/**
 * @brief State handler for MSTATE_SETUP.
 * Resets the transfer for starting and moves on to CONNECT.
 * @param[in,out] data  The transfer.
 * @return CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_setup(struct Curl_easy *data)
{
  const struct curltime *pnow = Curl_pgrs_now(data);
  Curl_pgrsTimeWas(data, TIMER_STARTSINGLE, *pnow);
  if(data->set.timeout)
    Curl_expire_set(data, EXPIRE_TIMEOUT, data->set.timeout, pnow);
  if(data->set.connecttimeout)
    /* Since a connection might go to pending and back to CONNECT several
       times before it actually takes off, we need to set the timeout once
       in SETUP before we enter CONNECT the first time. */
    Curl_expire_set(data, EXPIRE_CONNECTTIMEOUT,
                    data->set.connecttimeout, pnow);

  multistate(data, MSTATE_CONNECT);
  return CURLM_CALL_MULTI_PERFORM;
}

/**
 * @brief State handler for MSTATE_CONNECTING.
 * Drives the connection filters until connected or failed.
 * @param[in,out] data          The transfer.
 * @param[out]    stream_error  Set TRUE on a stream-only failure.
 * @param[out]    result        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_connecting(struct Curl_easy *data,
                                       bool *stream_error,
                                       CURLcode *result)
{
  bool connected;

  if(!data->conn) {
    DEBUGASSERT(0);
    *result = CURLE_FAILED_INIT;
    return CURLM_OK;
  }
  if(!Curl_xfer_recv_is_paused(data)) {
    *result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &connected);
    if(connected && !*result) {
      if(!data->conn->bits.reuse &&
         Curl_conn_is_multiplex(data->conn, FIRSTSOCKET)) {
        /* new connection, can multiplex, wake pending handles */
        multi_schedule_pending(data->multi);
      }
      multistate(data, MSTATE_PROTOCONNECT);
      return CURLM_CALL_MULTI_PERFORM;
    }
    else if(*result) {
      /* failure detected */
      CURL_TRC_M(data, "connect failed -> %d", (int)*result);
      multi_posttransfer(data);
      multi_done(data, *result, TRUE);
      *stream_error = TRUE;
      return CURLM_OK;
    }
  }
  return CURLM_OK;
}

/**
 * @brief State handler for MSTATE_PROTOCONNECT.
 * Starts the protocol level connect (login, handshake).
 * @param[in,out] data          The transfer.
 * @param[out]    stream_error  Set TRUE on a stream-only failure.
 * @param[out]    result        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_protoconnect(struct Curl_easy *data,
                                         bool *stream_error,
                                         CURLcode *result)
{
  bool protocol_connected = FALSE;

  if(!*result && data->conn->bits.reuse) {
    /* ftp seems to hang when protoconnect on reused connection since we
     * handle PROTOCONNECT in general inside the filters, it seems wrong to
     * restart this on a reused connection.
     */
    multistate(data, MSTATE_DO);
    return CURLM_CALL_MULTI_PERFORM;
  }
  if(!*result)
    *result = protocol_connect(data, &protocol_connected);
  if(!*result && !protocol_connected) {
    /* switch to waiting state */
    multistate(data, MSTATE_PROTOCONNECTING);
    return CURLM_CALL_MULTI_PERFORM;
  }
  else if(!*result) {
    /* protocol connect has completed, go WAITDO or DO */
    multistate(data, MSTATE_DO);
    return CURLM_CALL_MULTI_PERFORM;
  }

  /* failure detected */
  multi_posttransfer(data);
  multi_done(data, *result, TRUE);
  *stream_error = TRUE;
  return CURLM_OK;
}

/**
 * @brief State handler for MSTATE_PROTOCONNECTING.
 * Continues the protocol level connect.
 * @param[in,out] data          The transfer.
 * @param[out]    stream_error  Set TRUE on a stream-only failure.
 * @param[out]    result        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_protoconnecting(struct Curl_easy *data,
                                            bool *stream_error,
                                            CURLcode *result)
{
  bool protocol_connected = FALSE;

  /* protocol-specific connect phase */
  *result = protocol_connecting(data, &protocol_connected);
  if(!*result && protocol_connected) {
    /* after the connect has completed, go WAITDO or DO */
    multistate(data, MSTATE_DO);
    return CURLM_CALL_MULTI_PERFORM;
  }
  else if(*result) {
    /* failure detected */
    multi_posttransfer(data);
    multi_done(data, *result, TRUE);
    *stream_error = TRUE;
  }
  return CURLM_OK;
}

/**
 * @brief State handler for MSTATE_DOING.
 * Continues the non-blocking "do" phase.
 * @param[in,out] data          The transfer.
 * @param[out]    stream_error  Set TRUE on a stream-only failure.
 * @param[out]    result        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_doing(struct Curl_easy *data,
                                  bool *stream_error,
                                  CURLcode *result)
{
  bool dophase_done = FALSE;

  /* we continue DOING until the DO phase is complete */
  DEBUGASSERT(data->conn);
  *result = protocol_doing(data, &dophase_done);
  if(!*result) {
    if(dophase_done) {
      /* after DO, go DO_DONE or DO_MORE */
      multistate(data, data->conn->bits.do_more ?
                 MSTATE_DOING_MORE : MSTATE_DID);
      return CURLM_CALL_MULTI_PERFORM;
    } /* dophase_done */
  }
  else {
    /* failure detected */
    multi_posttransfer(data);
    multi_done(data, *result, FALSE);
    *stream_error = TRUE;
  }
  return CURLM_OK;
}

/**
 * @brief State handler for MSTATE_DOING_MORE.
 * Continues the multi-step "do more" phase of a protocol.
 * @param[in,out] data          The transfer.
 * @param[out]    stream_error  Set TRUE on a stream-only failure.
 * @param[out]    result        Transfer result on error.
 * @return CURLM_OK or CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_doing_more(struct Curl_easy *data,
                                       bool *stream_error,
                                       CURLcode *result)
{
  domore control;

  /*
   * When we are connected, DOING MORE and then go DID
   */
  DEBUGASSERT(data->conn);
  *result = multi_do_more(data, &control);

  if(!*result) {
    if(control != DOMORE_INCOMPLETE) {
      /* if DONE, advance to DO_DONE
         if GOBACK, go back to DOING */
      multistate(data, control == DOMORE_DONE ? MSTATE_DID : MSTATE_DOING);
      return CURLM_CALL_MULTI_PERFORM;
    }
    /* else
       stay in DO_MORE */
  }
  else {
    /* failure detected */
    multi_posttransfer(data);
    multi_done(data, *result, FALSE);
    *stream_error = TRUE;
  }
  return CURLM_OK;
}

/**
 * @brief State handler for MSTATE_DID.
 * Moves to PERFORMING, or straight to DONE when no data is to be moved.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer.
 * @return CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_did(struct Curl_multi *multi,
                                struct Curl_easy *data)
{
  DEBUGASSERT(data->conn);
  if(data->conn->bits.multiplex)
    /* Check if we can move pending requests to send pipe */
    multi_schedule_pending(multi); /* multiplexed */

  /* Only perform the transfer if there is a good socket to work with.
     Having both BAD is a signal to skip immediately to DONE */
  if(CONN_SOCK_IDX_VALID(data->conn->recv_idx) ||
     CONN_SOCK_IDX_VALID(data->conn->send_idx)) {
    multistate(data, MSTATE_PERFORMING);
    /* Do not return CURLM_CALL_MULTI_PERFORM to give other transfers
     * a chance to send off their requests.
     * Note: Some SFTP handlers do not seem to like this.
     *       Restrict it to HTTP families. */
    return ((multi->xfers_alive > 1) &&
            (data->conn->scheme->protocol & PROTO_FAMILY_HTTP)) ?
           CURLM_OK : CURLM_CALL_MULTI_PERFORM;
  }
  else {
#ifndef CURL_DISABLE_FTP
    if(data->state.wildcardmatch &&
       ((data->conn->scheme->flags & PROTOPT_WILDCARD) == 0)) {
      data->wildcard->state = CURLWC_DONE;
    }
#endif
    multistate(data, MSTATE_DONE);
    return CURLM_CALL_MULTI_PERFORM;
  }
}

/**
 * @brief State handler for MSTATE_DONE.
 * Runs multi_done() and moves the transfer to COMPLETED.
 * @param[in,out] data     The transfer.
 * @param[in,out] presult  In: result so far. Out: final result.
 * @return CURLM_CALL_MULTI_PERFORM.
 * @internal
 */
static CURLMcode multistate_done(struct Curl_easy *data, CURLcode *presult)
{
  if(data->conn) {
    CURLcode result;

    /* post-transfer command */
    result = multi_done(data, *presult, FALSE);

    /* allow a previously set error code take precedence */
    if(!(*presult))
      *presult = result;
  }

#ifndef CURL_DISABLE_FTP
  if(data->state.wildcardmatch) {
    if(data->wildcard->state != CURLWC_DONE) {
      /* if a wildcard is set and we are not ending -> lets start again
         with MSTATE_INIT */
      multistate(data, MSTATE_INIT);
      return CURLM_CALL_MULTI_PERFORM;
    }
  }
#endif
  /* after we have DONE what we are supposed to do, go COMPLETED, and
     it does not matter what the multi_done() returned! */
  multistate(data, MSTATE_COMPLETED);
  return CURLM_CALL_MULTI_PERFORM;
}

/**
 * @brief Run the state machine for one transfer as far as possible.
 * Dispatches to the multistate_*() handlers in a loop while they ask to
 * be called again, and queues a message when the transfer completes.
 * @param[in,out] multi        The multi handle.
 * @param[in,out] data         The transfer to run.
 * @param[in]     sigpipe_ctx  SIGPIPE handling context.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_RECURSIVE_API_CALL.
 * @internal
 */
static CURLMcode multi_runsingle(struct Curl_multi *multi,
                                 struct Curl_easy *data,
                                 struct Curl_sigpipe_ctx *sigpipe_ctx)
{
  CURLMcode mresult = CURLM_OK;
  CURLcode result = CURLE_OK;
  const struct curltime *pnow = NULL;

  if(multi->dead) {
    /* a multi-level callback returned error before, meaning every individual
     transfer now has failed */
    result = CURLE_ABORTED_BY_CALLBACK;
    multi_posttransfer(data);
    multi_done(data, result, FALSE);
    multistate(data, MSTATE_COMPLETED);
  }

  multi_warn_debug(multi, data);

  /* transfer runs now, clear the dirty bit. This may be set
   * again during processing, triggering a re-run later. */
  Curl_uint32_bset_remove(&multi->dirty, data->mid);

  if(data == multi->admin) {
#ifdef ENABLE_INTERNAL_WAKEUP
    /* Consume any pending wakeup signals before processing.
     * This is necessary for event based processing. See #21547 */
    (void)Curl_wakeup_consume(multi->wakeup_internal, TRUE);
#endif
#ifdef USE_RESOLV_THREADED
    Curl_async_thrdd_multi_process(multi);
#endif
    Curl_cshutdn_perform(&multi->cshutdn, multi->admin, sigpipe_ctx);
    goto out;
  }

  sigpipe_apply(data, sigpipe_ctx);
  do {
    /* A "stream" here is a logical stream if the protocol can handle that
       (HTTP/2), or the full connection for older protocols */
    bool stream_error = FALSE;
    mresult = CURLM_OK;
    pnow = NULL;

    if(multi_ischanged(multi, TRUE)) {
      CURL_TRC_M(data, "multi changed, check CONNECT_PEND queue");
      multi_schedule_pending(multi); /* multiplexed */
    }

    if(data->mstate > MSTATE_CONNECT &&
       data->mstate < MSTATE_COMPLETED) {
      /* Make sure we set the connection's current owner */
      DEBUGASSERT(data->conn);
      if(!data->conn) {
        mresult = CURLM_INTERNAL_ERROR;
        goto out;
      }
    }

    /* Wait for the connect state as only then is the start time stored, but
       we must not check already completed handles */
    if((data->mstate >= MSTATE_CONNECT) && (data->mstate < MSTATE_COMPLETED)) {
      pnow = Curl_pgrs_now(data);
      if(multi_handle_timeout(data, pnow, &stream_error, &result))
        /* Skip the statemachine and go directly to error handling section. */
        goto statemachine_end;
      pnow = NULL;
    }

    switch(data->mstate) {
    case MSTATE_INIT:
      /* Transitional state. init this transfer. A handle never comes back to
         this state. */
      mresult = multistate_init(data, &result);
      break;

    case MSTATE_SETUP:
      /* Transitional state. Setup things for a new transfer. The handle
         can come back to this state on a redirect. */
      mresult = multistate_setup(data);
      break;

    case MSTATE_CONNECT:
      mresult = multistate_connect(multi, data, &result);
      break;

    case MSTATE_CONNECTING:
      /* awaiting a completion of an asynch TCP connect */
      mresult = multistate_connecting(data, &stream_error, &result);
      break;

    case MSTATE_PROTOCONNECT:
      mresult = multistate_protoconnect(data, &stream_error, &result);
      break;

    case MSTATE_PROTOCONNECTING:
      /* protocol-specific connect phase */
      mresult = multistate_protoconnecting(data, &stream_error, &result);
      break;

    case MSTATE_DO:
      mresult = multistate_do(data, &stream_error, &result);
      break;

    case MSTATE_DOING:
      /* we continue DOING until the DO phase is complete */
      mresult = multistate_doing(data, &stream_error, &result);
      break;

    case MSTATE_DOING_MORE:
      /*
       * When we are connected, DOING MORE and then go DID
       */
      mresult = multistate_doing_more(data, &stream_error, &result);
      break;

    case MSTATE_DID:
      mresult = multistate_did(multi, data);
      break;

    case MSTATE_RATELIMITING: /* limit-rate exceeded in either direction */
      mresult = multistate_ratelimiting(data, &result);
      break;

    case MSTATE_PERFORMING:
      mresult = multistate_performing(data, &stream_error, &result);
      break;

    case MSTATE_DONE:
      mresult = multistate_done(data, &result);
      break;

    case MSTATE_COMPLETED:
      break;

    case MSTATE_PENDING:
    case MSTATE_MSGSENT:
      /* handles in these states should NOT be in this list */
      break;

    default:
      mresult = CURLM_INTERNAL_ERROR;
      goto out;
    }

    if(data->mstate >= MSTATE_CONNECT &&
       data->mstate < MSTATE_DO &&
       mresult != CURLM_CALL_MULTI_PERFORM &&
       !multi_ischanged(multi, FALSE)) {
      /* We now handle stream timeouts if and only if this will be the last
       * loop iteration. We only check this on the last iteration to ensure
       * that if we know we have additional work to do immediately
       * (i.e. CURLM_CALL_MULTI_PERFORM == TRUE) then we should do that before
       * declaring the connection timed out as we may almost have a completed
       * connection. */
      pnow = Curl_pgrs_now(data);
      multi_handle_timeout(data, pnow, &stream_error, &result);
    }

statemachine_end:
    if(!pnow)
      pnow = Curl_pgrs_now(data);
    result = is_finished(multi, data, pnow, stream_error, result);
    if(result)
      mresult = CURLM_CALL_MULTI_PERFORM;

    if(MSTATE_COMPLETED == data->mstate) {
      handle_completed(multi, data, result);
      mresult = CURLM_OK;
      goto out;
    }
  } while((mresult == CURLM_CALL_MULTI_PERFORM) ||
          multi_ischanged(multi, FALSE));

out:
  data->result = result;
  return mresult;
}

/**
 * @brief Run all transfers that are in process.
 * @param[in,out] multi            The multi handle.
 * @param[out]    running_handles  Number of still running transfers.
 * @return CURLM_OK or the first non-OK CURLMcode from a transfer.
 * @internal
 */
static CURLMcode multi_perform(struct Curl_multi *multi,
                               int *running_handles)
{
  CURLMcode returncode = CURLM_OK;
  struct curltime start;
  uint32_t mid;
  struct Curl_sigpipe_ctx sigpipe_ctx;

  curlx_pnow(&start);
  sigpipe_init(&sigpipe_ctx);

  if(Curl_uint32_bset_first(&multi->process, &mid)) {
    CURL_TRC_M(multi->admin, "multi_perform(running=%u)",
               multi_xfers_running(multi));
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      CURLMcode mresult;
      if(!data) {
        DEBUGASSERT(0);
        Curl_uint32_bset_remove(&multi->process, mid);
        Curl_uint32_bset_remove(&multi->dirty, mid);
        continue;
      }
      mresult = multi_runsingle(multi, data, &sigpipe_ctx);
      if(mresult)
        returncode = mresult;
    } while(Curl_uint32_bset_next(&multi->process, mid, &mid));
  }
  sigpipe_restore(&sigpipe_ctx);

  if(multi_ischanged(multi, TRUE))
    multi_schedule_pending(multi);

  if(!returncode && CURL_MNTFY_HAS_ENTRIES(multi))
    returncode = Curl_mntfy_dispatch_all(multi);

  /*
   * Remove all expired timers from the splay since handles are dealt
   * with unconditionally by this function and curl_multi_timeout() requires
   * that already passed/handled expire times are removed from the splay.
   *
   * It is important that the 'now' value is set at the entry of this function
   * and not for the current time as it may have ticked a little while since
   * then and then we risk this loop to remove timers that actually have not
   * been handled!
   */
  while(Curl_timeouts_remove_expired(&multi->timeouts, &start, &mid)) {
    /* the removed may have another timeout in queue */
    struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
    if(!data) {
      DEBUGASSERT(0);
      continue;
    }
    (void)add_next_timeout(&start, multi, data);
    if(data->mstate == MSTATE_PENDING) {
      bool stream_unused;
      CURLcode result_unused;
      if(multi_handle_timeout(data, Curl_pgrs_now(data),
                              &stream_unused, &result_unused)) {
        infof(data, "PENDING handle timeout");
        move_pending_to_connect(multi, data);
      }
    }
  }

  if(running_handles) {
    uint32_t running = multi_xfers_running(multi);
    *running_handles = (running < INT_MAX) ? (int)running : INT_MAX;
  }

  if(CURLM_OK >= returncode)
    returncode = Curl_update_timer(multi);

  return returncode;
}

/**
 * @brief Run transfers of a multi handle (public API).
 * @param[in]  m                The multi handle.
 * @param[out] running_handles  Number of transfers still running.
 * @return CURLM_OK or a CURLMcode error.
 * @see curl_multi_info_read()
 */
CURLMcode curl_multi_perform(CURLM *m, int *running_handles)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_perform, &mresult)) {
    mresult = multi_perform(m, running_handles);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Destroy a multi handle (public API).
 * Closes connections, removes remaining transfers and frees all
 * resources.
 * @param[in] m  The multi handle (NULL is accepted).
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_RECURSIVE_API_CALL.
 * @warning The handle is invalid after a successful return. Easy handles
 * still attached are detached, not freed.
 */
CURLMcode curl_multi_cleanup(CURLM *m)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_cleanup, &mresult)) {
    struct Curl_multi *multi = m;
    void *entry;
    uint32_t mid;

    /* First remove all remaining easy handles,
     * close internal ones. admin handle is special */
    if(Curl_uint32_tbl_first(&multi->xfers, &mid, &entry)) {
      do {
        struct Curl_easy *data = entry;
        if(!GOOD_EASY_HANDLE(data)) {
          mresult = CURLM_BAD_HANDLE;
          goto out;
        }

#ifdef DEBUGBUILD
        if(mid != data->mid) {
          CURL_TRC_M(data, "multi_cleanup: still present with mid=%u, "
                     "but unexpected data->mid=%u\n", mid, data->mid);
          DEBUGASSERT(0);
        }
#endif

        if(data == multi->admin)
          continue;

        if(!data->state.done && data->conn)
          /* if DONE was never called for this handle */
          (void)multi_done(data, CURLE_OK, TRUE);

        data->multi = NULL; /* clear the association */
        Curl_uint32_tbl_remove(&multi->xfers, mid);
        data->mid = UINT32_MAX;

#ifdef USE_LIBPSL
        if(data->psl == &multi->psl)
          data->psl = NULL;
#endif
        if(data->state.internal)
          Curl_close(&data);
      } while(Curl_uint32_tbl_next(&multi->xfers, mid, &mid, &entry));
    }

#ifdef USE_RESOLV_THREADED
    Curl_async_thrdd_multi_destroy(multi, !multi->quick_exit);
#endif
    Curl_cpool_destroy(&multi->cpool, multi->admin);
    Curl_cshutdn_destroy(&multi->cshutdn, multi->admin);
    if(multi->admin) {
      CURL_TRC_M(multi->admin, "multi_cleanup, closing admin handle, done");
      multi->admin->multi = NULL;
      Curl_uint32_tbl_remove(&multi->xfers, multi->admin->mid);
      Curl_close(&multi->admin);
    }

    multi->magic = 0; /* not good anymore */

    Curl_multi_ev_cleanup(multi);
    Curl_hash_destroy(&multi->proto_hash);
    Curl_dnscache_destroy(&multi->dnscache);
    Curl_psl_destroy(&multi->psl);
#ifdef USE_SSL
    Curl_ssl_scache_destroy(multi->ssl_scache);
#endif

#ifdef USE_WINSOCK
    WSACloseEvent(multi->wsa_event);
#endif
#ifdef ENABLE_WAKEUP
  Curl_wakeup_destroy(multi->wakeup_pair);
#endif
#ifdef ENABLE_INTERNAL_WAKEUP
  Curl_wakeup_destroy(multi->wakeup_internal);
#endif

    multi_xfer_bufs_free(multi);
    Curl_mntfy_cleanup(multi);
#ifdef DEBUGBUILD
    if(Curl_uint32_tbl_count(&multi->xfers)) {
      multi_xfer_tbl_dump(multi);
      DEBUGASSERT(0);
    }
#endif
    Curl_uint32_bset_destroy(&multi->process);
    Curl_uint32_bset_destroy(&multi->dirty);
    Curl_uint32_bset_destroy(&multi->pending);
    Curl_uint32_bset_destroy(&multi->msgsent);
    Curl_uint32_tbl_destroy(&multi->xfers);
    curlx_memzero(multi, sizeof(*multi));
    curlx_free(multi);

    mresult = CURLM_OK;
  }
out:
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/*
 * curl_multi_info_read()
 *
 * This function is the primary way for a multi/multi_socket application to
 * figure out if a transfer has ended.
 */

/**
 * @brief Read the next completion message (public API).
 * @param[in]  m              The multi handle.
 * @param[out] msgs_in_queue  Messages remaining in the queue (may be NULL).
 * @return The next CURLMsg, or NULL when there is none.
 * @warning The returned struct is owned by libcurl and valid only until
 * the next call into the multi handle.
 */
CURLMsg *curl_multi_info_read(CURLM *m, int *msgs_in_queue)
{
  struct Curl_mapi_guard guard;
  CURLMsg *msg_result = NULL;

  *msgs_in_queue = 0; /* default to none */
  if(CURL_MAPI_ENTER(&guard, m, multi_info_read, NULL)) {
    struct Curl_multi *multi = m;
    uint32_t mid;
    if(Curl_uint32_bset_first(&multi->msgsent, &mid)) {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);

      DEBUGASSERT(data);
      Curl_uint32_bset_remove(&multi->msgsent, mid);
      *msgs_in_queue =
        curlx_uztosi(Curl_uint32_bset_count(&multi->msgsent));
      if(data)
        msg_result = &data->msg;
    }
  }
  CURL_MAPI_LEAVE(&guard);
  return msg_result;
}

/**
 * @brief Tell the multi that a socket is about to be closed.
 * @param[in,out] data  The transfer owning the socket.
 * @param[in]     s     The socket that will be closed.
 */
void Curl_multi_will_close(struct Curl_easy *data, curl_socket_t s)
{
  if(data) {
    struct Curl_multi *multi = data->multi;
    if(multi) {
      CURL_TRC_M(data, "Curl_multi_will_close fd=%" FMT_SOCKET_T, s);
      Curl_multi_ev_socket_done(multi, data, s);
    }
  }
}

/**
 * @brief Initialize the timeout list of a transfer.
 * @param[in,out] data  The transfer.
 * @internal
 */
static void multi_timeouts_init(struct Curl_easy *data)
{
  data->state.timeouts.first = EXPIRE_LAST;
  data->state.timeouts.splaynode.registered = FALSE;
}

/**
 * @brief Advance to a transfer's next timeout.
 * Each Curl_easy has a list of timeouts. add_next_timeout() is called
 * when it has been removed from the splay tree because the timeout has
 * expired. It advances in the list to pick the next timeout to use (skip
 * the already expired ones) and adds this node back to the splay tree.
 *
 * The splay tree only has each Curl_easy as a single node and the nearest
 * timeout is used to sort it on.
 * @param[in]     pnow   Current time.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The transfer.
 * @return CURLM_OK or CURLM_OUT_OF_MEMORY.
 * @internal
 */
static CURLMcode add_next_timeout(const struct curltime *pnow,
                                  struct Curl_multi *multi,
                                  struct Curl_easy *data)
{
  struct expire_timers *timeouts = &data->state.timeouts;
  timediff_t now_us = Curl_timeouts_offset_us(&multi->timeouts, pnow);

  while(timeouts->first < EXPIRE_LAST) {
    if(timeouts->offset_us[timeouts->first] <= now_us)  /* already expired */
      timeouts->first = timeouts->next[timeouts->first];
    else /* timeouts are sorted, first is first in the future now */
      break;
  }

  if(timeouts->first < EXPIRE_LAST) {
    /* Insert this node again into the splay. Keep the timer in the list in
       case we need to recompute future timers. */
    Curl_timeouts_add(&multi->timeouts, data,
                      timeouts->offset_us[timeouts->first]);
  }
  return CURLM_OK;
}

/**
 * @brief Mark transfers with expired timers as dirty.
 * @param[in,out] multi  The multi handle.
 * @param[in]     ts     Current time to compare timers against.
 * @internal
 */
static void multi_mark_expired_as_dirty(struct Curl_multi *multi,
                                        const struct curltime *ts)
{
  struct Curl_easy *data = NULL;
  uint32_t mid;

  /*
   * The loop following here will go on as long as there are expire-times left
   * to process (compared to `ts`) in the splay and 'data' will be
   * re-assigned for every expired handle we deal with.
   */
  while(Curl_timeouts_remove_expired(&multi->timeouts, ts, &mid)) {
    /* Check if there is one (more) expired timer to deal with! This function
       extracts a matching node if there is one */
    data = Curl_multi_get_easy(multi, mid);
    if(!data) {
      DEBUGASSERT(0);
      continue;
    }
#ifdef CURLVERBOSE
    if(CURL_TRC_TIMER_is_verbose(data)) {
      if(data->state.timeouts.first < EXPIRE_LAST) {
        CURL_TRC_TIMER(data, data->state.timeouts.first, "has expired");
      }
    }
#endif
    (void)add_next_timeout(ts, multi, data);
    Curl_multi_mark_dirty(data);
  }
}

/**
 * @brief Run all transfers marked dirty.
 * @param[in,out] multi        The multi handle.
 * @param[in]     sigpipe_ctx  SIGPIPE handling context.
 * @param[out]    pnum         Number of transfers that were run.
 * @return CURLM_OK or the first error from a transfer.
 * @internal
 */
static CURLMcode multi_run_dirty(struct Curl_multi *multi,
                                 struct Curl_sigpipe_ctx *sigpipe_ctx,
                                 uint32_t *pnum)
{
  CURLMcode mresult = CURLM_OK;
  uint32_t mid;

  *pnum = 0;
  if(Curl_uint32_bset_first(&multi->dirty, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        CURL_TRC_M(data, "multi_run_dirty");

        if(!Curl_uint32_bset_contains(&multi->process, mid)) {
          if(Curl_uint32_bset_contains(&multi->pending, mid)) {
            /* Something happened on the pending transfer, act on it. */
            move_pending_to_connect(multi, data);
          }
          else {
            /* We are no longer processing this transfer */
            Curl_uint32_bset_remove(&multi->dirty, mid);
            continue;
          }
        }

        (*pnum)++;
        /* runsingle() clears the dirty mid */
        mresult = multi_runsingle(multi, data, sigpipe_ctx);

        if(CURLM_OK >= mresult) {
          /* reassess event handling of data */
          mresult = Curl_multi_ev_assess_xfer(multi, data);
          if(mresult)
            goto out;
        }
      }
      else {
        CURL_TRC_M(multi->admin, "multi_run_dirty, %u no longer found", mid);
        Curl_uint32_bset_remove(&multi->dirty, mid);
      }
    } while(Curl_uint32_bset_next(&multi->dirty, mid, &mid));
  }

out:
  return mresult;
}

/**
 * @brief Common implementation of the socket action API.
 * @param[in,out] multi            The multi handle.
 * @param[in]     checkall         TRUE to check all transfers (_all()).
 * @param[in]     s                Socket with activity or
 *                                 CURL_SOCKET_TIMEOUT.
 * @param[in]     ev_bitmask       CURL_CSELECT_* flags for the socket.
 * @param[out]    running_handles  Number of transfers still running.
 * @return CURLM_OK or a CURLMcode error.
 * @internal
 */
static CURLMcode multi_socket(struct Curl_multi *multi,
                              bool checkall,
                              curl_socket_t s,
                              int ev_bitmask,
                              int *running_handles)
{
  CURLMcode mresult = CURLM_OK;
  struct Curl_sigpipe_ctx pipe_ctx;
  struct curltime now;
  uint32_t run_xfers;

  (void)ev_bitmask;
  sigpipe_init(&pipe_ctx);

  if(checkall) {
    /* *perform() deals with running_handles on its own */
    mresult = multi_perform(multi, running_handles);

    if(mresult != CURLM_BAD_HANDLE) {
      /* Reassess event status of all active transfers, but keep any error
         from multi_perform() */
      CURLMcode mresult2 =
        Curl_multi_ev_assess_xfer_bset(multi, &multi->process);
      if(!mresult)
        mresult = mresult2;
    }
    goto out;
  }

  if(s != CURL_SOCKET_TIMEOUT) {
    /* Mark all transfers of that socket as dirty */
    Curl_multi_ev_dirty_xfers(multi, s);
  }
  else {
    /* Asked to run due to time-out. Clear the 'last_expire_ts' variable to
       force Curl_update_timer() to trigger a callback to the app again even
       if the same timeout is still the one to run after this call. That
       handles the case when the application asks libcurl to run the timeout
       prematurely. */
    multi->last_expire_offset_us = 0;

    /* Applications may set `socket_cb` *after* having added transfers
     * first. *Then* kick off processing with a
     * curl_multi_socket_action(TIMEOUT) afterwards. Make sure our
     * admin handle registers its pollset with the callbacks present. */
    mresult = multi_assess_wakeup(multi);
    if(mresult)
      goto out;
  }

  curlx_pnow(&now);
  multi_mark_expired_as_dirty(multi, &now);
  mresult = multi_run_dirty(multi, &pipe_ctx, &run_xfers);
  if(mresult)
    goto out;

  if(run_xfers) {
    /* Running transfers takes time. With a new timestamp, we might catch
     * other expires which are due now. Instead of telling the application
     * to set a 0 timeout and call us again, we run them here.
     * Do that only once or it might be unfair to transfers on other
     * sockets. */
    curlx_pnow(&now);
    multi_mark_expired_as_dirty(multi, &now);
    mresult = multi_run_dirty(multi, &pipe_ctx, &run_xfers);
  }

out:
  sigpipe_restore(&pipe_ctx);

  if(multi_ischanged(multi, TRUE))
    multi_schedule_pending(multi);

  if(!mresult && CURL_MNTFY_HAS_ENTRIES(multi))
    mresult = Curl_mntfy_dispatch_all(multi);

  if(running_handles) {
    uint32_t running = multi_xfers_running(multi);
    *running_handles = (running < INT_MAX) ? (int)running : INT_MAX;
  }

  if(CURLM_OK >= mresult)
    mresult = Curl_update_timer(multi);
  return mresult;
}

#undef curl_multi_setopt
/**
 * @brief Set an option on a multi handle (public API).
 * @param[in,out] m       The multi handle.
 * @param[in]     option  The CURLMOPT_* option.
 * @param[in]     ...     The option value (type depends on option).
 * @return CURLM_OK, CURLM_BAD_HANDLE, CURLM_UNKNOWN_OPTION,
 *         CURLM_BAD_FUNCTION_ARGUMENT or CURLM_RECURSIVE_API_CALL.
 */
CURLMcode curl_multi_setopt(CURLM *m, CURLMoption option, ...)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult = CURLM_OK;

  if(CURL_MAPI_ENTER(&guard, m, multi_setopt, &mresult)) {
    struct Curl_multi *multi = m;
    va_list param;
    unsigned long uarg;
    size_t szarg;

    va_start(param, option);

    switch(option) {
    case CURLMOPT_SOCKETFUNCTION:
      multi->socket_cb = va_arg(param, curl_socket_callback);
      break;
    case CURLMOPT_SOCKETDATA:
      multi->socket_userp = va_arg(param, void *);
      break;
    case CURLMOPT_PUSHFUNCTION:
      multi->push_cb = va_arg(param, curl_push_callback);
      break;
    case CURLMOPT_PUSHDATA:
      multi->push_userp = va_arg(param, void *);
      break;
    case CURLMOPT_PIPELINING:
      multi->multiplexing = va_arg(param, long) & CURLPIPE_MULTIPLEX ? 1 : 0;
      break;
    case CURLMOPT_TIMERFUNCTION:
      multi->timer_cb = va_arg(param, curl_multi_timer_callback);
      break;
    case CURLMOPT_TIMERDATA:
      multi->timer_userp = va_arg(param, void *);
      break;
    case CURLMOPT_MAXCONNECTS:
      uarg = va_arg(param, unsigned long);
      if(uarg <= UINT32_MAX)
        multi->maxconnects = (uint32_t)uarg;
      break;
    case CURLMOPT_MAX_HOST_CONNECTIONS:
      if(!curlx_sltouz(va_arg(param, long), &szarg))
        mresult = CURLM_BAD_FUNCTION_ARGUMENT;
      multi->max_host_connections = (szarg < UINT32_MAX) ?
                                    (uint32_t)szarg : UINT32_MAX;
      break;
    case CURLMOPT_MAX_TOTAL_CONNECTIONS:
      if(!curlx_sltouz(va_arg(param, long), &szarg))
        mresult = CURLM_BAD_FUNCTION_ARGUMENT;
      multi->max_total_connections = (szarg < UINT32_MAX) ?
                                     (uint32_t)szarg : UINT32_MAX;
      break;
      /* options formerly used for pipelining */
    case CURLMOPT_MAX_PIPELINE_LENGTH:
      break;
    case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
      break;
    case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:
      break;
    case CURLMOPT_PIPELINING_SITE_BL:
      break;
    case CURLMOPT_PIPELINING_SERVER_BL:
      break;
    case CURLMOPT_MAX_CONCURRENT_STREAMS: {
      if(!curlx_sltouz(va_arg(param, long), &szarg) ||
         !szarg || (szarg > (size_t)INT_MAX)) /* preserve previous cutoff */
        multi->max_concurrent_streams = 100;
      else
        multi->max_concurrent_streams = (szarg < UINT32_MAX) ?
                                       (uint32_t)szarg : UINT32_MAX;
      break;
    }
    case CURLMOPT_NETWORK_CHANGED: {
      long val = va_arg(param, long);
      if(val & CURLMNWC_CLEAR_ALL)
        /* In the beginning, all values available to set were 1 by mistake. We
           converted this to mean "all", thus setting all the bits
           automatically */
        val = CURLMNWC_CLEAR_DNS | CURLMNWC_CLEAR_CONNS;
      if(val & CURLMNWC_CLEAR_DNS) {
        Curl_dnscache_clear(multi->admin);
      }
      if(val & CURLMNWC_CLEAR_CONNS) {
        Curl_cpool_nw_changed(&multi->cpool, multi->admin);
      }
      break;
    }
    case CURLMOPT_NOTIFYFUNCTION:
      multi->ntfy.ntfy_cb = va_arg(param, curl_notify_callback);
      break;
    case CURLMOPT_NOTIFYDATA:
      multi->ntfy.ntfy_cb_data = va_arg(param, void *);
      break;
    case CURLMOPT_RESOLVE_THREADS_MAX:
#ifdef USE_RESOLV_THREADED
      uarg = va_arg(param, long);
      if((uarg <= 0) || (uarg > UINT32_MAX))
        mresult = CURLM_BAD_FUNCTION_ARGUMENT;
      else {
        CURLcode result = Curl_async_thrdd_multi_set_props(
          multi, 0, (uint32_t)uarg, 2000);
        switch(result) {
        case CURLE_OK:
          mresult = CURLM_OK;
          break;
        case CURLE_BAD_FUNCTION_ARGUMENT:
          mresult = CURLM_BAD_FUNCTION_ARGUMENT;
          break;
        case CURLE_OUT_OF_MEMORY:
          mresult = CURLM_OUT_OF_MEMORY;
          break;
        default:
          mresult = CURLM_INTERNAL_ERROR;
          break;
        }
      }
#endif
      break;
    case CURLMOPT_QUICK_EXIT:
      multi->quick_exit = va_arg(param, long) ? 1 : 0;
      break;
    default:
      mresult = CURLM_UNKNOWN_OPTION;
      break;
    }
    va_end(param);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/* we define curl_multi_socket() in the public multi.h header */
#undef curl_multi_socket

/**
 * @brief Deprecated socket action call without event bitmask.
 * @param[in]  m                The multi handle.
 * @param[in]  s                Socket with activity.
 * @param[out] running_handles  Number of transfers still running.
 * @return CURLM_OK or a CURLMcode error.
 * @deprecated Use curl_multi_socket_action().
 */
CURLMcode curl_multi_socket(CURLM *m, curl_socket_t s, int *running_handles)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_socket, &mresult)) {
    mresult = multi_socket(m, FALSE, s, 0, running_handles);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Tell the multi handle about socket activity (public API).
 * @param[in]  m                The multi handle.
 * @param[in]  s                Socket with activity or
 *                              CURL_SOCKET_TIMEOUT.
 * @param[in]  ev_bitmask       CURL_CSELECT_* flags.
 * @param[out] running_handles  Number of transfers still running.
 * @return CURLM_OK or a CURLMcode error.
 */
CURLMcode curl_multi_socket_action(CURLM *m, curl_socket_t s,
                                   int ev_bitmask, int *running_handles)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_socket_action, &mresult)) {
    mresult = multi_socket(m, FALSE, s, ev_bitmask, running_handles);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Deprecated: check all transfers for socket activity.
 * @param[in]  m                The multi handle.
 * @param[out] running_handles  Number of transfers still running.
 * @return CURLM_OK or a CURLMcode error.
 * @deprecated Use curl_multi_socket_action().
 */
CURLMcode curl_multi_socket_all(CURLM *m, int *running_handles)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_socket_all, &mresult)) {
    mresult = multi_socket(m, TRUE, CURL_SOCKET_BAD, 0, running_handles);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Tell if any transfer is marked dirty.
 * @param[in] multi  The multi handle.
 * @return TRUE if there is at least one dirty transfer.
 * @internal
 */
static bool multi_has_dirties(struct Curl_multi *multi)
{
  uint32_t mid;
  if(Curl_uint32_bset_first(&multi->dirty, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        if(Curl_uint32_bset_contains(&multi->process, mid))
          return TRUE;
        /* We are no longer processing this transfer */
        Curl_uint32_bset_remove(&multi->dirty, mid);
      }
      else {
        CURL_TRC_M(multi->admin, "dirty transfer %u no longer found", mid);
        Curl_uint32_bset_remove(&multi->dirty, mid);
      }
    } while(Curl_uint32_bset_next(&multi->dirty, mid, &mid));
  }
  return FALSE;
}

/**
 * @brief Compute the time until the next timeout.
 * @param[in]  multi             The multi handle.
 * @param[out] pexire_offset_us  Time offset in microseconds, or -1.
 * @param[out] timeout_ms        Milliseconds to wait, -1 for none.
 * @internal
 */
static void multi_timeout(struct Curl_multi *multi,
                          timediff_t *pexire_offset_us,
                          int *timeout_ms)
{
  if(multi->dead) {
    if(pexire_offset_us)
      *pexire_offset_us = 0;
    *timeout_ms = 0;
    return;
  }

  if(multi_has_dirties(multi)) {
    if(pexire_offset_us) {
      struct curltime now;
      curlx_pnow(&now);
      *pexire_offset_us = Curl_timeouts_offset_us(&multi->timeouts, &now);
    }
    *timeout_ms = 0;
    return;
  }
  else {
    struct curltime now;
    uint32_t mid;

    curlx_pnow(&now);
    *timeout_ms = Curl_timeouts_next_ms(&multi->timeouts, &now,
                                        pexire_offset_us, &mid);
#ifdef CURLVERBOSE
    if(mid != UINT32_MAX) {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data && CURL_TRC_TIMER_is_verbose(data) &&
         (data->state.timeouts.first < EXPIRE_LAST)) {
        CURL_TRC_TIMER(data, data->state.timeouts.first,
                       "gives multi timeout in %dms", *timeout_ms);
      }
    }
#endif
  }
}

/**
 * @brief Get how long to wait before calling into the multi handle.
 * @param[in]  m           The multi handle.
 * @param[out] timeout_ms  Milliseconds to wait, or -1 if no timeout.
 * @return CURLM_OK or CURLM_BAD_HANDLE.
 */
CURLMcode curl_multi_timeout(CURLM *m,
                             long *timeout_ms)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_timeout, &mresult)) {
    int itimeout_ms;

    multi_timeout(m, NULL, &itimeout_ms);
    *timeout_ms = (long)itimeout_ms;
    mresult = CURLM_OK;
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Tell the application to update its timer.
 * Notifies the application, if it subscribes to the update timer
 * callback (CURLMOPT_TIMERFUNCTION), when the timeout changed.
 * @param[in,out] multi  The multi handle.
 * @return CURLM_OK or CURLM_ABORTED_BY_CALLBACK.
 */
CURLMcode Curl_update_timer(struct Curl_multi *multi)
{
  timediff_t timeouts_offset_us = 0;
  int timeout_ms;
  int rc;
  bool set_value = FALSE;

  if(!multi->timer_cb || multi->dead)
    return CURLM_OK;
  multi_timeout(multi, &timeouts_offset_us, &timeout_ms);

  if(timeout_ms < 0 && !multi->last_timeout_set) {
    /* nothing to do */
  }
  else if(timeout_ms < 0) {
    /* there is no timeout now but there was one previously */
    CURL_TRC_M(multi->admin, "[TIMER] clear");
    timeout_ms = -1; /* normalize */
    set_value = TRUE;
  }
  else if(!multi->last_timeout_set) {
    CURL_TRC_M(multi->admin, "[TIMER] set %dms, none before", timeout_ms);
    set_value = TRUE;
  }
  else if(multi->last_expire_offset_us != timeouts_offset_us) {
    /* We had a timeout before and have one now, the absolute timestamp
     * differs. The relative timeout_ms may be the same, but the starting
     * point differs. Let the application restart its timer. */
    CURL_TRC_M(multi->admin, "[TIMER] set %dms, replace previous",
               timeout_ms);
    set_value = TRUE;
  }
  else {
    /* We have same expire time as previously. Our relative 'timeout_ms'
     * may be different now, but the application has the timer running
     * and we do not to tell it to start this again. */
  }

  if(set_value) {
    struct Curl_mapi_guard guard;

    multi->last_expire_offset_us = timeouts_offset_us;
    multi->last_timeout_set = timeout_ms >= 0;
    CURL_CBAPI_MULTI_START(&guard, multi, multi_timer_cb);
    rc = multi->timer_cb(multi, timeout_ms, multi->timer_userp);
    CURL_CBAPI_MULTI_END(&guard);
    if(rc == -1) {
      multi->dead = TRUE;
      return CURLM_ABORTED_BY_CALLBACK;
    }
  }
  return CURLM_OK;
}

#ifdef DEBUGBUILD
/**
 * @brief Check whether a transfer has expired timers.
 * @param[in] data  The transfer.
 * @return TRUE if any timeout has expired.
 * @internal
 */
static bool multi_timeouts_check(struct Curl_easy *data)
{
  struct expire_timers *timeouts = &data->state.timeouts;
  uint8_t id;
  int i = 0;
  for(id = timeouts->first; id < EXPIRE_LAST; id = timeouts->next[id]) {
    if(++i >= EXPIRE_LAST) {
      failf(data, "expire timeouts looped: %d iterations and no end", i);
      return FALSE;
    }
    if(id == timeouts->next[id]) {
      failf(data, "expire timeouts wrong: %d points to itself", (int)id);
      return FALSE;
    }
    if((timeouts->next[id] < EXPIRE_LAST) &&
       (timeouts->offset_us[id] > timeouts->offset_us[timeouts->next[id]])) {
      failf(data, "expire timeouts not sorted: %d happens after %d but "
            "is listed before", (int)id, (int)timeouts->next[id]);
      return FALSE;
    }
  }
  return TRUE;
}
#endif

/**
 * @brief Remove a given timestamp from the list of timeouts.
 * @param[in,out] data  The transfer.
 * @param[in]     eid   Id of the timeout to remove.
 * @internal
 */
static void multi_clear_timeout(struct Curl_easy *data, expire_id eid)
{
  struct expire_timers *timeouts = &data->state.timeouts;
  uint8_t orig_first = timeouts->first;
  uint8_t *anchor = &timeouts->first;
  uint8_t id = (uint8_t)eid;

  if((unsigned)eid >= EXPIRE_LAST) {
    DEBUGASSERT(0);
    return;
  }

  while(*anchor < EXPIRE_LAST) {
    if(*anchor == id) {
      *anchor = timeouts->next[id];
      break;
    }
    anchor = &timeouts->next[*anchor];
  }
  DEBUGASSERT(multi_timeouts_check(data));
  if(Curl_timeouts_has(data)) {
    struct Curl_multi *multi = data->multi;

    if(!multi) {
      DEBUGASSERT(0);
      return;
    }
    if((timeouts->first >= EXPIRE_LAST) || /* no more timeouts */
       (timeouts->first != orig_first)) {  /* active timeout changed */
      Curl_timeouts_remove(&multi->timeouts, data);
    }
    if((timeouts->first < EXPIRE_LAST) && !Curl_timeouts_has(data)) {
      Curl_timeouts_add(&multi->timeouts, data,
                        timeouts->offset_us[timeouts->first]);
    }
  }
}

/**
 * @brief Add a timestamp to the list of timeouts.
 * Keeps the list sorted so that head of list is always the timeout
 * nearest in time.
 * @param[in,out] data   The transfer.
 * @param[in]     stamp  The time the timer fires.
 * @param[in]     eid    Id of the timeout.
 * @return CURLM_OK or CURLM_OUT_OF_MEMORY.
 * @internal
 */
static CURLMcode multi_set_timeout(struct Curl_easy *data,
                                   const struct curltime *stamp,
                                   expire_id eid)
{
  struct expire_timers *timeouts = &data->state.timeouts;
  uint8_t *anchor = &timeouts->first;
  uint8_t id = (uint8_t)eid;

  if((unsigned)eid >= EXPIRE_LAST) {
    DEBUGASSERT(0);
    return CURLM_BAD_FUNCTION_ARGUMENT;
  }
  /* remove from list, store time and re-insert */
  multi_clear_timeout(data, eid);
  timeouts->offset_us[id] =
    Curl_timeouts_offset_us(&data->multi->timeouts, stamp);

  while(*anchor < EXPIRE_LAST) {
    if(timeouts->offset_us[*anchor] > timeouts->offset_us[id])
      break;
    anchor = &timeouts->next[*anchor];
  }
  timeouts->next[eid] = *anchor;
  timeouts->next[eid] = *anchor;
  *anchor = id;
  DEBUGASSERT(multi_timeouts_check(data));
  CURL_TRC_TIMER(data, eid, "set for %" FMT_TIMEDIFF_T "us",
                 curlx_ptimediff_us(stamp, Curl_pgrs_now(data)));
  return CURLM_OK;
}

/**
 * @brief Set an expire timer from a relative time.
 * Given a number of milliseconds from now to use to set the 'act before
 * this'-time for the transfer, to be extracted by curl_multi_timeout().
 *
 * The timeout will be added to a queue of timeouts if it defines a moment
 * in time that is later than the current head of queue.
 *
 * Expire replaces a former timeout using the same id if already set.
 * @param[in,out] data  The transfer.
 * @param[in]     eid   Id of the timeout.
 * @param[in]     ms    Milliseconds from `pnow`.
 * @param[in]     pnow  Current time.
 */
void Curl_expire_set(struct Curl_easy *data,
                     expire_id eid, timediff_t ms,
                     const struct curltime *pnow)
{
  struct Curl_multi *multi = data->multi;
  struct expire_timers *timeouts = &data->state.timeouts;
  uint8_t prev_id = timeouts->first;
  struct curltime set;

  /* this is only interesting while there is still an associated multi struct
     remaining! */
  if(!multi)
    return;
  DEBUGASSERT(eid < EXPIRE_LAST);
  if(ms > INT_MAX)
    /* Cap ridiculous timeouts, 31-bit ms is still 3.5 weeks. When the time
       goes to the user, it must fit in this size. */
    ms = INT_MAX;

  set = *pnow;
  set.tv_sec += (time_t)(ms / 1000); /* may be a 64 to 32-bit conversion */
  set.tv_usec += (int)(ms % 1000) * 1000;
  if(set.tv_usec >= 1000000) {
    set.tv_sec++;
    set.tv_usec -= 1000000;
  }

  /* Add the timeout, will replace any previous value for this timer. */
  multi_set_timeout(data, &set, eid);
  DEBUGASSERT(timeouts->first < EXPIRE_LAST);

  if(Curl_timeouts_has(data)) {
    /* data has already a timeout registered. If the first timer
     * was NOT the one we just set AND is still the first one,
     * nothing changed from the timeouts point of view. The
     * set timer triggers after the one already registered. Leave. */
    if((prev_id != eid) && (prev_id == timeouts->first))
      return;

    /* Since this is an updated time, we must remove data from
     * timeouts and then add it again. */
    Curl_timeouts_remove(&multi->timeouts, data);
  }

  /* Insert the new timer expiry since it is our local minimum. */
  Curl_timeouts_add(&multi->timeouts, data,
                    timeouts->offset_us[timeouts->first]);
}

/**
 * @brief Set an expire timer from the current time.
 * @param[in,out] data   The transfer.
 * @param[in]     milli  Milliseconds from now.
 * @param[in]     eid    Id of the timeout.
 * @see Curl_expire_set()
 */
void Curl_expire(struct Curl_easy *data,
                 timediff_t milli, expire_id eid)
{
  Curl_expire_set(data, eid, milli, Curl_pgrs_now(data));
}

/**
 * @brief Remove the expire timer with the given id. Marks it as done.
 * @param[in,out] data  The transfer.
 * @param[in]     eid   Id of the timeout to clear.
 */
void Curl_expire_clear(struct Curl_easy *data, expire_id eid)
{
  /* remove the timer, if there */
  multi_clear_timeout(data, eid);
  CURL_TRC_TIMER(data, eid, "cleared");
}

/**
 * @brief Clear ALL timeout values for this handle.
 * @param[in,out] data  The transfer.
 */
void Curl_expire_clear_all(struct Curl_easy *data)
{
  struct Curl_multi *multi = data->multi;

  /* this is only interesting while there is still an associated multi struct
     remaining! */
  if(!multi)
    return;

  if(Curl_timeouts_remove(&multi->timeouts, data)) {
    /* Since this is an cleared time, we must remove the previous entry from
       the splay tree */
    multi_timeouts_init(data);

    if(data->id >= 0)
      CURL_TRC_M(data, "[TIMEOUT] all cleared");
  }
}

/**
 * @brief Associate application data with a socket (public API).
 * @param[in,out] m       The multi handle.
 * @param[in]     sockfd  The socket.
 * @param[in]     sockp   Application pointer for the socket callback.
 * @return CURLM_OK, CURLM_BAD_HANDLE, CURLM_BAD_SOCKET or
 *         CURLM_OUT_OF_MEMORY.
 */
CURLMcode curl_multi_assign(CURLM *m, curl_socket_t sockfd,
                            void *sockp)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult;

  if(CURL_MAPI_ENTER(&guard, m, multi_assign, &mresult)) {
    mresult = Curl_multi_ev_assign(m, sockfd, sockp);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Move a PENDING transfer back to CONNECT.
 * @param[in,out] multi  The multi handle.
 * @param[in,out] data   The pending transfer.
 * @internal
 */
static void move_pending_to_connect(struct Curl_multi *multi,
                                    struct Curl_easy *data)
{
  DEBUGASSERT(data->mstate == MSTATE_PENDING);

  /* Remove this node from the pending set, add into process set */
  Curl_uint32_bset_remove(&multi->pending, data->mid);
  Curl_uint32_bset_add(&multi->process, data->mid);

  multistate(data, MSTATE_CONNECT);
  Curl_multi_mark_dirty(data); /* make it run */
}

/**
 * @brief Move transfers from PENDING back to CONNECT.
 * Moves a handle from PENDING back into the process list and changes
 * state to CONNECT.
 *
 * We do not move all transfers because that can be a significant amount.
 * Since this is tried every now and then doing too many too often becomes
 * a performance problem.
 *
 * When there is a change for connection limits like max host connections
 * etc, this likely only allows one new transfer. When there is a pipewait
 * change, it can potentially allow hundreds of new transfers.
 *
 * We could consider an improvement where we store the queue reason and
 * allow more pipewait rechecks than others.
 * @param[in,out] multi  The multi handle.
 * @internal
 */
static void multi_schedule_pending(struct Curl_multi *multi)
{
  uint32_t mid = multi->last_pending_mid;

  if(mid) {
    while(Curl_uint32_bset_next(&multi->pending, mid, &mid)) {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        move_pending_to_connect(multi, data);
        multi->last_pending_mid = mid;
        return;
      }
      /* transfer no longer known, should not happen */
      Curl_uint32_bset_remove(&multi->pending, mid);
      DEBUGASSERT(0);
    }
    /* found no pending transfers with `mid` larger than `last_pending_mid`.
     * Start at the beginning of the pending set again. */
    multi->last_pending_mid = 0;
  }

  if(Curl_uint32_bset_first(&multi->pending, &mid)) {
    do {
      struct Curl_easy *data = Curl_multi_get_easy(multi, mid);
      if(data) {
        move_pending_to_connect(multi, data);
        multi->last_pending_mid = mid;
        return;
      }
      /* transfer no longer known, should not happen */
      Curl_uint32_bset_remove(&multi->pending, mid);
      DEBUGASSERT(0);
    } while(Curl_uint32_bset_next(&multi->pending, mid, &mid));
  }
}

/**
 * @brief Maximum number of concurrent streams per connection.
 * @param[in] multi  The multi handle.
 * @return The CURLMOPT_MAX_CONCURRENT_STREAMS value.
 */
uint32_t Curl_multi_max_concurrent_streams(struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  return multi->max_concurrent_streams;
}

/**
 * @brief Get all easy handles of a multi handle (public API).
 * @param[in] m  The multi handle.
 * @return A NULL-terminated array of handles, or NULL on error.
 * @warning The caller must free the array with curl_free().
 */
CURL **curl_multi_get_handles(CURLM *m)
{
  struct Curl_mapi_guard guard;
  CURL **a = NULL;

  if(CURL_MAPI_ENTER(&guard, m, multi_get_handles, NULL)) {
    struct Curl_multi *multi = m;
    void *entry;
    size_t count = Curl_uint32_tbl_count(&multi->xfers);

    a = curlx_malloc(sizeof(struct Curl_easy *) * (count + 1));
    if(a) {
      unsigned int i = 0;
      uint32_t mid;

      if(Curl_uint32_tbl_first(&multi->xfers, &mid, &entry)) {
        do {
          struct Curl_easy *data = entry;
          DEBUGASSERT(i < count);
          if(!data->state.internal)
            a[i++] = data;
        } while(Curl_uint32_tbl_next(&multi->xfers, mid, &mid, &entry));
      }
      a[i] = NULL; /* last entry is a NULL */
    }
  }
  CURL_MAPI_LEAVE(&guard);
  return a;
}

/**
 * @brief Get a numeric multi handle information value.
 * @param[in]  m       The multi handle.
 * @param[in]  info    The CURLMINFO_* item.
 * @param[out] pvalue  Receives the value.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_UNKNOWN_OPTION.
 */
CURLMcode curl_multi_get_offt(CURLM *m,
                              CURLMinfo_offt info,
                              curl_off_t *pvalue)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult = CURLM_OK;

  if(CURL_MAPI_ENTER(&guard, m, multi_get_offt, &mresult)) {
    struct Curl_multi *multi = m;
    uint32_t n;

    if(!pvalue) {
      mresult = CURLM_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    switch(info) {
    case CURLMINFO_XFERS_CURRENT:
      n = Curl_uint32_tbl_count(&multi->xfers);
      if(n && multi->admin)
        --n;
      *pvalue = (curl_off_t)n;
      break;
    case CURLMINFO_XFERS_RUNNING:
      n = Curl_uint32_bset_count(&multi->process);
      if(n && Curl_uint32_bset_contains(&multi->process, multi->admin->mid))
        --n;
      *pvalue = (curl_off_t)n;
      break;
    case CURLMINFO_XFERS_PENDING:
      *pvalue = (curl_off_t)Curl_uint32_bset_count(&multi->pending);
      break;
    case CURLMINFO_XFERS_DONE:
      *pvalue = (curl_off_t)Curl_uint32_bset_count(&multi->msgsent);
      break;
    case CURLMINFO_XFERS_ADDED:
      *pvalue = multi->xfers_total_ever;
      break;
    default:
      *pvalue = -1;
      mresult = CURLM_UNKNOWN_OPTION;
      break;
    }
  }
out:
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Allocate a fixed-size transfer buffer.
 * @param[in] len  Size of the buffer in bytes.
 * @return The new buffer, or NULL on out of memory.
 * @internal
 */
static struct Curl_fixed_buf *fixed_buf_create(size_t len)
{
  struct Curl_fixed_buf *fbuf;
  if((SIZE_MAX - sizeof(*fbuf)) < len)
    return NULL; /* too large */
  fbuf = curlx_malloc(len + sizeof(*fbuf));
  if(fbuf)
    fbuf->len = len;
  return fbuf;
}

/**
 * @brief Borrow the shared transfer buffer.
 * @param[in,out] data     The transfer.
 * @param[out]    pbuf     Receives the buffer.
 * @param[out]    pbuflen  Receives the buffer length.
 * @return CURLE_OK, CURLE_OUT_OF_MEMORY or CURLE_FAILED_INIT.
 * @warning Only one borrower at a time; must be released again.
 * @see Curl_multi_xfer_buf_release()
 */
CURLcode Curl_multi_xfer_buf_borrow(struct Curl_easy *data,
                                    char **pbuf, size_t *pbuflen)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  *pbuf = NULL;
  *pbuflen = 0;
  if(!data->multi) {
    failf(data, "transfer has no multi handle");
    return CURLE_FAILED_INIT;
  }
  if(!data->set.buffer_size) {
    failf(data, "transfer buffer size is 0");
    return CURLE_FAILED_INIT;
  }
  if(data->multi->xfer_buf_borrowed) {
    failf(data, "attempt to borrow xfer_buf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_buf &&
     data->set.buffer_size > data->multi->xfer_buf->len) {
    /* not large enough, get a new one */
    curlx_safefree(data->multi->xfer_buf);
  }

  if(!data->multi->xfer_buf) {
    data->multi->xfer_buf =
      fixed_buf_create(curlx_uitouz(data->set.buffer_size));
    if(!data->multi->xfer_buf) {
      failf(data, "could not allocate xfer_buf of %u bytes",
            data->set.buffer_size);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  data->multi->xfer_buf_borrowed = TRUE;
  *pbuf = data->multi->xfer_buf->data;
  *pbuflen = data->multi->xfer_buf->len;
  return CURLE_OK;
}

/**
 * @brief Release the shared transfer buffer.
 * @param[in,out] data  The transfer.
 * @param[in]     buf   The buffer that was borrowed.
 */
void Curl_multi_xfer_buf_release(struct Curl_easy *data, char *buf)
{
  (void)buf;
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  DEBUGASSERT(!buf || (data->multi->xfer_buf &&
                       data->multi->xfer_buf->data == buf));
  data->multi->xfer_buf_borrowed = FALSE;
}

/**
 * @brief Borrow the shared upload buffer.
 * @param[in,out] data     The transfer.
 * @param[out]    pbuf     Receives the buffer.
 * @param[out]    pbuflen  Receives the buffer length.
 * @return CURLE_OK, CURLE_OUT_OF_MEMORY or CURLE_FAILED_INIT.
 * @warning Only one borrower at a time; must be released again.
 * @see Curl_multi_xfer_ulbuf_release()
 */
CURLcode Curl_multi_xfer_ulbuf_borrow(struct Curl_easy *data,
                                      char **pbuf, size_t *pbuflen)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  *pbuf = NULL;
  *pbuflen = 0;
  if(!data->multi) {
    failf(data, "transfer has no multi handle");
    return CURLE_FAILED_INIT;
  }
  if(data->multi->xfer_ulbuf_borrowed) {
    failf(data, "attempt to borrow xfer_ulbuf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_ulbuf &&
     data->set.upload_buffer_size > data->multi->xfer_ulbuf->len) {
    /* not large enough, get a new one */
    curlx_safefree(data->multi->xfer_ulbuf);
  }

  if(!data->multi->xfer_ulbuf) {
    data->multi->xfer_ulbuf =
      fixed_buf_create(curlx_uitouz(data->set.upload_buffer_size));
    if(!data->multi->xfer_ulbuf) {
      failf(data, "could not allocate xfer_ulbuf of %u bytes",
            data->set.upload_buffer_size);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  data->multi->xfer_ulbuf_borrowed = TRUE;
  *pbuf = data->multi->xfer_ulbuf->data;
  *pbuflen = data->multi->xfer_ulbuf->len;
  return CURLE_OK;
}

/**
 * @brief Release the shared upload buffer.
 * @param[in,out] data  The transfer.
 * @param[in]     buf   The buffer that was borrowed.
 */
void Curl_multi_xfer_ulbuf_release(struct Curl_easy *data, char *buf)
{
  (void)buf;
  DEBUGASSERT(data);
  DEBUGASSERT(data->multi);
  DEBUGASSERT(!buf || (data->multi->xfer_ulbuf &&
                       data->multi->xfer_ulbuf->data == buf));
  data->multi->xfer_ulbuf_borrowed = FALSE;
}

/**
 * @brief Borrow the shared socket buffer of at least `blen` bytes.
 * @param[in,out] data  The transfer.
 * @param[in]     blen  Minimum size needed.
 * @param[out]    pbuf  Receives the buffer.
 * @return CURLE_OK, CURLE_OUT_OF_MEMORY or CURLE_FAILED_INIT.
 * @warning Only one borrower at a time; must be released again.
 * @see Curl_multi_xfer_sockbuf_release()
 */
CURLcode Curl_multi_xfer_sockbuf_borrow(struct Curl_easy *data,
                                        size_t blen, char **pbuf)
{
  DEBUGASSERT(data);
  *pbuf = NULL;
  if(!data->multi) {
    /* When a SHARE gets destroyed and has a connection pool, we get
     * call with share->admin which does not have a multi handle. */
    *pbuf = curlx_malloc(blen);
    return *pbuf ? CURLE_OK : CURLE_OUT_OF_MEMORY;
  }
  if(data->multi->xfer_sockbuf_borrowed) {
    failf(data, "attempt to borrow xfer_sockbuf when already borrowed");
    return CURLE_AGAIN;
  }

  if(data->multi->xfer_sockbuf && blen > data->multi->xfer_sockbuf->len) {
    /* not large enough, get a new one */
    curlx_safefree(data->multi->xfer_sockbuf);
  }

  if(!data->multi->xfer_sockbuf) {
    data->multi->xfer_sockbuf = fixed_buf_create(blen);
    if(!data->multi->xfer_sockbuf) {
      failf(data, "could not allocate xfer_sockbuf of %zu bytes", blen);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  data->multi->xfer_sockbuf_borrowed = TRUE;
  *pbuf = data->multi->xfer_sockbuf->data;
  return CURLE_OK;
}

/**
 * @brief Release the shared socket buffer.
 * @param[in,out] data  The transfer.
 * @param[in]     buf   The buffer that was borrowed.
 */
void Curl_multi_xfer_sockbuf_release(struct Curl_easy *data, char *buf)
{
  DEBUGASSERT(data);
  if(!data->multi) {
    /* When a SHARE gets destroyed and has a connection pool, we get
     * call with share->admin which does not have a multi handle. */
    curlx_free(buf);
  }
  else {
    DEBUGASSERT(!buf || (data->multi->xfer_sockbuf &&
                         data->multi->xfer_sockbuf->data == buf));
    data->multi->xfer_sockbuf_borrowed = FALSE;
  }
}

/**
 * @brief Free the shared transfer buffers of a multi handle.
 * @param[in,out] multi  The multi handle.
 * @pre No buffer is currently borrowed.
 * @internal
 */
static void multi_xfer_bufs_free(struct Curl_multi *multi)
{
  DEBUGASSERT(multi);
  curlx_safefree(multi->xfer_buf);
  multi->xfer_buf_borrowed = FALSE;
  curlx_safefree(multi->xfer_ulbuf);
  multi->xfer_ulbuf_borrowed = FALSE;
  curlx_safefree(multi->xfer_sockbuf);
  multi->xfer_sockbuf_borrowed = FALSE;
}

/**
 * @brief Look up a transfer by its id.
 * @param[in] multi  The multi handle.
 * @param[in] mid    The transfer id.
 * @return The transfer, or NULL if unknown.
 */
struct Curl_easy *Curl_multi_get_easy(struct Curl_multi *multi,
                                      uint32_t mid)
{
  struct Curl_easy *data = Curl_uint32_tbl_get(&multi->xfers, mid);
  if(GOOD_EASY_HANDLE(data))
    return data;
  CURL_TRC_M(multi->admin, "invalid easy handle in xfer table for mid=%u",
             mid);
  Curl_uint32_tbl_remove(&multi->xfers, mid);
  return NULL;
}

/**
 * @brief Tell if a transfer is registered in the multi handle.
 * @param[in] multi  The multi handle.
 * @param[in] data   The transfer.
 * @return TRUE if known.
 */
bool Curl_multi_knows_easy(struct Curl_multi *multi, struct Curl_easy *data)
{
  return Curl_uint32_tbl_get(&multi->xfers, data->mid) == data;
}

/**
 * @brief Get the number of transfers currently in process/pending.
 * @param[in] multi  The multi handle.
 * @return Number of running transfers.
 * @internal
 */
static uint32_t multi_xfers_running(struct Curl_multi *multi)
{
  if(!multi) {
    DEBUGASSERT(0);
    return 0;
  }
  return multi->xfers_alive;
}

/**
 * @brief Number of transfers attached to the multi handle.
 * @param[in] multi  The multi handle.
 * @return The transfer count.
 */
uint32_t Curl_multi_xfers_attached(struct Curl_multi *multi)
{
  if(!multi || !multi->admin) {
    DEBUGASSERT(0);
    return 0;
  }
  /* Discount the admin handle */
  return Curl_uint32_tbl_count(&multi->xfers) - 1;
}

/**
 * @brief Mark a transfer dirty so that it runs on the next call.
 * @param[in,out] data  The transfer.
 */
void Curl_multi_mark_dirty(struct Curl_easy *data)
{
  if(data->multi && data->mid != UINT32_MAX)
    Curl_uint32_bset_add(&data->multi->dirty, data->mid);
}

/**
 * @brief Clear the dirty mark of a transfer.
 * @param[in,out] data  The transfer.
 */
void Curl_multi_clear_dirty(struct Curl_easy *data)
{
  if(data->multi && data->mid != UINT32_MAX)
    Curl_uint32_bset_remove(&data->multi->dirty, data->mid);
}

/**
 * @brief Enable a notification type (public API).
 * @param[in,out] m             The multi handle.
 * @param[in]     notification  A CURLMNOTIFY_* value.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_UNKNOWN_OPTION.
 */
CURLMcode curl_multi_notify_enable(CURLM *m, unsigned int notification)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult = CURLM_OK;

  if(CURL_MAPI_ENTER(&guard, m, multi_notify_enable, &mresult)) {
    mresult = Curl_mntfy_enable(m, notification);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

/**
 * @brief Disable a notification type (public API).
 * @param[in,out] m             The multi handle.
 * @param[in]     notification  A CURLMNOTIFY_* value.
 * @return CURLM_OK, CURLM_BAD_HANDLE or CURLM_UNKNOWN_OPTION.
 */
CURLMcode curl_multi_notify_disable(CURLM *m, unsigned int notification)
{
  struct Curl_mapi_guard guard;
  CURLMcode mresult = CURLM_OK;

  if(CURL_MAPI_ENTER(&guard, m, multi_notify_disable, &mresult)) {
    mresult = Curl_mntfy_disable(m, notification);
  }
  CURL_MAPI_LEAVE(&guard);
  return mresult;
}

#ifdef DEBUGBUILD
/**
 * @brief Debug-dump one entry of the transfer table.
 * @param[in] multi  The multi handle.
 * @param[in] mid    Transfer id.
 * @param[in] entry  The table entry.
 * @internal
 */
static void multi_xfer_dump(struct Curl_multi *multi, uint32_t mid,
                            void *entry)
{
  struct Curl_easy *data = entry;

  (void)multi;
  if(!data) {
    curl_mfprintf(stderr, "mid=%u, entry=NULL, bug in xfer table?\n", mid);
  }
  else {
    curl_mfprintf(stderr, "mid=%u, magic=%s, p=%p, id=%" FMT_OFF_T
                  ", url=%s\n",
                  mid,
                  (data->magic == CURLEASY_MAGIC_NUMBER) ? "GOOD" : "BAD!",
                  (void *)data, data->id, Curl_bufref_ptr(&data->state.url));
  }
}

/**
 * @brief Debug-dump the whole transfer table.
 * @param[in] multi  The multi handle.
 * @internal
 */
static void multi_xfer_tbl_dump(struct Curl_multi *multi)
{
  uint32_t mid;
  void *entry;
  curl_mfprintf(stderr, "=== multi xfer table (count=%u, capacity=%u\n",
                Curl_uint32_tbl_count(&multi->xfers),
                Curl_uint32_tbl_capacity(&multi->xfers));
  if(Curl_uint32_tbl_first(&multi->xfers, &mid, &entry)) {
    multi_xfer_dump(multi, mid, entry);
    while(Curl_uint32_tbl_next(&multi->xfers, mid, &mid, &entry))
      multi_xfer_dump(multi, mid, entry);
  }
  curl_mfprintf(stderr, "===\n");
  fflush(stderr);
}
#endif /* DEBUGBUILD */

/** @} */
