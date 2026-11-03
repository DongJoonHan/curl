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
 * @file easy.c
 * @brief Easy interface: global init/cleanup and the curl_easy_* API.
 *
 * Implements the public "easy" API of libcurl. It contains the process
 * wide initialization and cleanup (curl_global_init() and friends), the
 * creation, duplication, reset and cleanup of easy handles, the blocking
 * transfer driver curl_easy_perform() (built on a private multi handle),
 * pause/unpause, connect-only send/receive, connection upkeep, TLS session
 * import/export and the per-handle meta data store.
 *
 * Debug builds additionally contain an event based transfer engine
 * (curl_easy_perform_ev()) used by the test suite to exercise the
 * curl_multi_socket_action() code paths.
 *
 * @note The easy handle itself is not thread-safe: one handle must not be
 *       used from several threads at the same time. The global init and
 *       cleanup functions are only thread-safe when libcurl was built with
 *       GLOBAL_INIT_IS_THREADSAFE.
 *
 * @defgroup easy Easy interface
 * @brief Public curl_easy_* API and global initialization.
 * @{
 */
#include "curl_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "urldata.h"
#include "api.h"
#include "transfer.h"
#include "vdns/hostip.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "vquic/vquic.h"
#include "url.h"
#include "getinfo.h"
#include "curlx/strdup.h"
#include "easyif.h"
#include "multiif.h"
#include "multi_ev.h"
#include "select.h"
#include "cfilters.h"
#include "sendf.h"
#include "curl_trc.h"
#include "connect.h" /* for Curl_getconnectinfo */
#include "slist.h"
#include "mime.h"
#include "amigaos.h"
#include "macos.h"
#include "curlx/wait.h"
#include "sigpipe.h"
#include "vssh/ssh.h"
#include "setopt.h"
#include "http_digest.h"
#include "curlx/dynbuf.h"
#include "bufref.h"
#include "altsvc.h"
#include "hsts.h"
#include "curl_sspi.h" /* Curl_sspi_global_init()/Curl_sspi_global_cleanup() */
#include "curlx/timeval.h" /* for curlx_now_init() */
#include "curlx/version_win32.h" /* for curlx_verify_windows_init() */

#include "easy_lock.h"

/**
 * @name Global initialization state
 * @brief True globals shared by curl_global_init() and
 *        curl_global_cleanup().
 * @{
 */
/** Reference count of successful curl_global_init() calls. */
static unsigned int initialized;
#ifdef USE_WINSOCK
/** TRUE if this library called WSAStartup() and must call WSACleanup(). */
static bool winsock_initialized;
#endif

#ifdef GLOBAL_INIT_IS_THREADSAFE

/** Lock serializing the global init, cleanup, trace and sslset calls. */
static curl_simple_lock s_lock = CURL_SIMPLE_LOCK_INIT;
/** @brief Take the global init lock (no-op without thread-safe init). */
#define global_init_lock()   curl_simple_lock_lock(&s_lock)
/** @brief Release the global init lock (no-op without thread-safe init). */
#define global_init_unlock() curl_simple_lock_unlock(&s_lock)

#else

#define global_init_lock()
#define global_init_unlock()

#endif

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(push)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

/** @} */

/**
 * @name Memory function pointers
 * @brief Allocator callbacks used by all of libcurl.
 *
 * If a memory-using function (like curl_getenv) is used before
 * curl_global_init() is called, these pointers must already be set, so
 * they default to the C library allocators. curl_global_init_mem() can
 * replace them.
 *
 * @warning They are plain globals; replacing them while other threads use
 *          libcurl is not safe.
 * @{
 */
/** malloc replacement. */
curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;
/** free replacement. */
curl_free_callback Curl_cfree = (curl_free_callback)free;
/** realloc replacement. */
curl_realloc_callback Curl_crealloc = (curl_realloc_callback)realloc;
/** strdup replacement. */
curl_strdup_callback Curl_cstrdup = (curl_strdup_callback)CURLX_STRDUP_LOW;
/** calloc replacement. */
curl_calloc_callback Curl_ccalloc = (curl_calloc_callback)calloc;

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif

#ifdef DEBUGBUILD
/** @} */

/**
 * @brief Debug builds only: deliberate allocation to detect a missing
 *        curl_global_cleanup() (set when CURL_GLOBAL_INIT is in the
 *        environment).
 */
static char *leakpointer;
#endif

/**
 * @internal
 * @brief Do the actual global initialization of libcurl.
 *
 * curl_global_init() globally initializes curl given a bitwise set of the
 * different features of what to initialize. Calls are reference counted:
 * only the first one does the work, later ones just bump the counter.
 * On failure the counter increase is undone.
 *
 * @param[in] flags        Bitmask of CURL_GLOBAL_* features. Only
 *                         CURL_GLOBAL_WINSOCK is acted upon here.
 * @param[in] memoryfuncs  TRUE to reset the memory callbacks to the C
 *                         library defaults, FALSE to keep user supplied
 *                         ones (curl_global_init_mem()).
 *
 * @return CURLE_OK on success (or when already initialized).
 * @return CURLE_FAILED_INIT if any sub-system (trace, SSPI, Winsock, TLS,
 *         hash, QUIC, Amiga, macOS, async resolver, SSH) fails to init.
 *
 * @pre The global init lock must be held by the caller.
 * @see curl_global_init(), curl_global_cleanup()
 */
static CURLcode global_init(long flags, bool memoryfuncs)
{
  (void)flags;

  if(initialized++)
    return CURLE_OK;

  if(memoryfuncs) {
    /* Setup the default memory functions here (again) */
    Curl_cmalloc = (curl_malloc_callback)malloc;
    Curl_cfree = (curl_free_callback)free;
    Curl_crealloc = (curl_realloc_callback)realloc;
    Curl_cstrdup = (curl_strdup_callback)CURLX_STRDUP_LOW;
    Curl_ccalloc = (curl_calloc_callback)calloc;
  }

#ifdef _WIN32
  curlx_verify_windows_init();
  curlx_now_init();
#endif

  if(Curl_trc_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_trc_init failed\n"));
    goto fail;
  }

#ifdef USE_WINDOWS_SSPI
  if(Curl_sspi_global_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_sspi_global_init() failed\n"));
    goto fail;
  }
#endif

#ifdef USE_WINSOCK
  /* CURL_GLOBAL_WINSOCK controls the *optional* part of the Windows
     initialization which is for the Windows sockets library (Winsock). */
  if(flags & CURL_GLOBAL_WINSOCK) {
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa)) {
      DEBUGF(curl_mfprintf(stderr, "Error: WSAStartup() failed\n"));
      goto fail;
    }
    winsock_initialized = TRUE;
  }
#endif

  if(!Curl_ssl_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_ssl_init failed\n"));
    goto fail;
  }

  if(Curl_hash_global_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_hash_global_init failed\n"));
    goto fail;
  }

  if(!Curl_vquic_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_vquic_init failed\n"));
    goto fail;
  }

  if(Curl_amiga_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_amiga_init failed\n"));
    goto fail;
  }

  if(Curl_macos_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_macos_init failed\n"));
    goto fail;
  }

  if(Curl_async_global_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_async_global_init failed\n"));
    goto fail;
  }

  if(Curl_ssh_init()) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_ssh_init failed\n"));
    goto fail;
  }

#ifdef DEBUGBUILD
  if(getenv("CURL_GLOBAL_INIT"))
    /* alloc data that will leak if *cleanup() is not called! */
    leakpointer = curlx_malloc(1);
#endif

  return CURLE_OK;

fail:
#ifdef USE_WINSOCK
  if(winsock_initialized) {
    WSACleanup();
    winsock_initialized = FALSE;
  }
#endif
  initialized--; /* undo the increase */
  return CURLE_FAILED_INIT;
}

/**
 * @brief Globally initialize libcurl.
 *
 * curl_global_init() globally initializes curl given a bitwise set of the
 * different features of what to initialize. It should be called once
 * before any other libcurl function; every call must be matched by a call
 * to curl_global_cleanup().
 *
 * @param[in] flags  Bitmask of CURL_GLOBAL_* values.
 *
 * @return CURLE_OK on success.
 * @return CURLE_FAILED_INIT if initialization failed.
 *
 * @warning Not thread-safe unless built with GLOBAL_INIT_IS_THREADSAFE.
 * @see curl_global_init_mem(), curl_global_cleanup()
 */
CURLcode curl_global_init(long flags)
{
  CURLcode result;
  global_init_lock();

  result = global_init(flags, TRUE);

  global_init_unlock();

  return result;
}

/**
 * @brief Globally initialize libcurl and register memory callbacks.
 *
 * curl_global_init_mem() globally initializes curl and also registers the
 * user provided callback routines. If libcurl is already initialized the
 * callbacks are ignored, but the reference counter is still incremented so
 * that the same number of cleanup calls is required.
 *
 * @param[in] flags  Bitmask of CURL_GLOBAL_* values.
 * @param[in] m      malloc replacement, must not be NULL.
 * @param[in] f      free replacement, must not be NULL.
 * @param[in] r      realloc replacement, must not be NULL.
 * @param[in] s      strdup replacement, must not be NULL.
 * @param[in] c      calloc replacement, must not be NULL.
 *
 * @return CURLE_OK on success.
 * @return CURLE_FAILED_INIT if any callback is NULL or init failed.
 *
 * @warning The callbacks must stay valid until the last matching
 *          curl_global_cleanup() has run.
 */
CURLcode curl_global_init_mem(long flags, curl_malloc_callback m,
                              curl_free_callback f, curl_realloc_callback r,
                              curl_strdup_callback s, curl_calloc_callback c)
{
  CURLcode result;

  /* Invalid input, return immediately */
  if(!m || !f || !r || !s || !c)
    return CURLE_FAILED_INIT;

  global_init_lock();

  if(initialized) {
    /* Already initialized, do not do it again, but bump the variable anyway to
       work like curl_global_init() and require the same amount of cleanup
       calls. */
    initialized++;
    global_init_unlock();
    return CURLE_OK;
  }

  /* set memory functions before global_init() in case it wants memory
     functions */
  Curl_cmalloc = m;
  Curl_cfree = f;
  Curl_cstrdup = s;
  Curl_crealloc = r;
  Curl_ccalloc = c;

  /* Call the actual init function, but without setting */
  result = global_init(flags, FALSE);

  global_init_unlock();

  return result;
}

/**
 * @brief Globally clean up libcurl.
 *
 * curl_global_cleanup() globally cleanups curl. Only the call that drops
 * the reference counter to zero releases the global resources (SSH, TLS,
 * QUIC, async resolver, Amiga, Winsock, SSPI). Calling it without a
 * matching init is a no-op.
 *
 * @warning All easy and multi handles must be cleaned up before the last
 *          call. Not thread-safe unless built with
 *          GLOBAL_INIT_IS_THREADSAFE.
 */
void curl_global_cleanup(void)
{
  global_init_lock();

  if(!initialized) {
    global_init_unlock();
    return;
  }

  if(--initialized) {
    global_init_unlock();
    return;
  }

  Curl_ssh_cleanup();
  Curl_ssl_cleanup();
  Curl_vquic_cleanup();
  Curl_async_global_cleanup();
  Curl_amiga_cleanup();

#ifdef USE_WINSOCK
  if(winsock_initialized) {
    WSACleanup();
    winsock_initialized = FALSE;
  }
#endif

#ifdef USE_WINDOWS_SSPI
  Curl_sspi_global_cleanup();
#endif

#ifdef DEBUGBUILD
  curlx_free(leakpointer);
#endif

  global_init_unlock();
}

/**
 * @brief Configure the global logging (trace) options.
 *
 * curl_global_trace() globally initializes curl logging.
 *
 * @param[in] config  Trace configuration string, e.g. "all,-http/2".
 *
 * @return CURLE_OK on success, or when verbose strings are disabled in
 *         this build (the option is then ignored).
 * @return Other CURLcode errors from parsing the configuration.
 */
CURLcode curl_global_trace(const char *config)
{
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  CURLcode result;
  global_init_lock();

  result = Curl_trc_opt(config);

  global_init_unlock();

  return result;
#else
  (void)config;
  return CURLE_OK;
#endif
}

/**
 * @brief Select the TLS backend to use, or list the available ones.
 *
 * curl_global_sslset() globally initializes the SSL backend to use.
 *
 * @param[in]  id     Backend id, or CURLSSLBACKEND_NONE to select by name.
 * @param[in]  name   Backend name, used when @p id is none; may be NULL.
 * @param[out] avail  Optional; receives a NULL terminated list of the
 *                    available backends. The list is owned by libcurl.
 *
 * @return CURLSSLSET_OK if the backend was selected.
 * @return CURLSSLSET_UNKNOWN_BACKEND if the backend is not known.
 * @return CURLSSLSET_TOO_LATE if a backend is already in use.
 * @return CURLSSLSET_NO_BACKENDS if libcurl has no TLS support.
 *
 * @note Must be called before curl_global_init().
 */
CURLsslset curl_global_sslset(curl_sslbackend id, const char *name,
                              const curl_ssl_backend ***avail)
{
  CURLsslset rc;

  global_init_lock();

  rc = Curl_init_sslset_nolock(id, name, avail);

  global_init_unlock();

  return rc;
}

/**
 * @brief Allocate and initialize a new easy handle.
 *
 * curl_easy_init() is the external interface to alloc, setup and init an
 * easy handle that is returned. If anything goes wrong, NULL is returned.
 * Performs a default curl_global_init() if the application has not.
 *
 * @return A new easy handle on success, to be released with
 *         curl_easy_cleanup().
 * @return NULL on failure (global init failed or out of memory).
 *
 * @warning The implicit global init is not thread-safe unless built with
 *          GLOBAL_INIT_IS_THREADSAFE; call curl_global_init() explicitly
 *          in multi-threaded programs.
 * @see curl_easy_cleanup(), curl_easy_duphandle()
 */
CURL *curl_easy_init(void)
{
  CURLcode result;
  struct Curl_easy *data;

  /* Make sure we inited the global SSL stuff */
  global_init_lock();

  if(!initialized) {
    result = global_init(CURL_GLOBAL_DEFAULT, TRUE);
    if(result) {
      /* something in the global init failed, return nothing */
      DEBUGF(curl_mfprintf(stderr, "Error: curl_global_init failed\n"));
      global_init_unlock();
      return NULL;
    }
  }
  global_init_unlock();

  /* We use Curl_open() with undefined URL so far */
  result = Curl_open(&data);
  if(result) {
    DEBUGF(curl_mfprintf(stderr, "Error: Curl_open failed\n"));
    return NULL;
  }

  return data;
}

#ifdef DEBUGBUILD

/**
 * @internal
 * @brief Debug builds: a node in the list of sockets the event based
 *        engine monitors.
 */
struct socketmonitor {
  struct socketmonitor *next; /**< next node in the list or NULL */
  struct pollfd socket; /**< socket info of what to monitor */
};

/**
 * @internal
 * @brief Debug builds: state of the event based transfer engine.
 */
struct events {
  long ms;              /**< timeout, run timeout function when reached */
  bool msbump;          /**< set TRUE when timeout is set by callback */
  int num_sockets;      /**< number of nodes in the monitor list */
  struct socketmonitor *list; /**< list of sockets to monitor */
  int running_handles;  /**< store the returned number */
};

/** Set to 1 to print poll() related tracing from the event engine. */
#define DEBUG_EV_POLL   0

/**
 * @internal
 * @brief Multi timer callback of the event engine.
 *
 * Callback that gets called with a new value when the timeout should be
 * updated. Stores the timeout and flags that it was bumped.
 *
 * @param[in]     multi       The multi handle (unused).
 * @param[in]     timeout_ms  New timeout in milliseconds, -1 for none.
 * @param[in,out] userp       The struct events to update.
 *
 * @return Always 0.
 */
static int events_timer(CURLM *multi,    /* multi handle */
                        long timeout_ms, /* see above */
                        void *userp)     /* private callback pointer */
{
  struct events *ev = userp;
  (void)multi;
#if DEBUG_EV_POLL
  curl_mfprintf(stderr, "events_timer: set timeout %ldms\n", timeout_ms);
#endif
  ev->ms = timeout_ms;
  ev->msbump = TRUE;
  return 0;
}

/**
 * @internal
 * @brief Convert poll() event bits to CURL_CSELECT_* bits.
 *
 * @param[in] pollmask  Mask of POLLIN, POLLOUT and POLLERR.
 *
 * @return The equivalent CURL_CSELECT_IN/OUT/ERR mask.
 */
static int poll2cselect(int pollmask)
{
  int omask = 0;
  if(pollmask & POLLIN)
    omask |= CURL_CSELECT_IN;
  if(pollmask & POLLOUT)
    omask |= CURL_CSELECT_OUT;
  if(pollmask & POLLERR)
    omask |= CURL_CSELECT_ERR;
  return omask;
}

/**
 * @internal
 * @brief Convert CURL_POLL_* bits to poll() event bits.
 *
 * @param[in] pollmask  Mask of CURL_POLL_IN and CURL_POLL_OUT.
 *
 * @return The equivalent POLLIN/POLLOUT mask.
 */
static short socketcb2poll(int pollmask)
{
  short omask = 0;
  if(pollmask & CURL_POLL_IN)
    omask |= POLLIN;
  if(pollmask & CURL_POLL_OUT)
    omask |= POLLOUT;
  return omask;
}

/**
 * @internal
 * @brief Multi socket callback of the event engine.
 *
 * Callback that gets called with information about socket activity to
 * monitor. Adds, updates or removes the socket in the monitor list.
 *
 * @param[in]     easy     Easy handle the socket belongs to.
 * @param[in]     s        The socket.
 * @param[in]     what     CURL_POLL_IN/OUT/INOUT/REMOVE.
 * @param[in,out] userp    The struct events holding the monitor list.
 * @param[in]     socketp  Private socket pointer (unused).
 *
 * @return 0 on success.
 * @return CURLE_OUT_OF_MEMORY if a list node could not be allocated.
 */
static int events_socket(CURL *easy,      /* easy handle */
                         curl_socket_t s, /* socket */
                         int what,        /* see above */
                         void *userp,     /* private callback
                                             pointer */
                         void *socketp)   /* private socket
                                             pointer */
{
  struct events *ev = userp;
  struct socketmonitor *m;
  struct socketmonitor *prev = NULL;
  bool found = FALSE;
  struct Curl_easy *data = easy;

#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)easy;
#endif
  (void)socketp;

  m = ev->list;
  while(m) {
    if(m->socket.fd == s) {
      found = TRUE;
      if(what == CURL_POLL_REMOVE) {
        struct socketmonitor *nxt = m->next;
        /* remove this node from the list of monitored sockets */
        if(prev)
          prev->next = nxt;
        else
          ev->list = nxt;
        curlx_free(m);
        infof(data, "socket cb: socket %" FMT_SOCKET_T " REMOVED", s);
      }
      else {
        /* The socket 's' is already being monitored, update the activity
           mask. Convert from libcurl bitmask to the poll one. */
        m->socket.events = socketcb2poll(what);
        infof(data, "socket cb: socket %" FMT_SOCKET_T " UPDATED as %s%s", s,
              (what & CURL_POLL_IN) ? "IN" : "",
              (what & CURL_POLL_OUT) ? "OUT" : "");
      }
      break;
    }
    prev = m;
    m = m->next; /* move to next node */
  }

  if(!found) {
    if(what == CURL_POLL_REMOVE) {
      /* should not happen if our logic is correct, but is no drama. */
      DEBUGF(infof(data, "socket cb: asked to REMOVE socket %"
                   FMT_SOCKET_T "but not present!", s));
      DEBUGASSERT(0);
    }
    else {
      m = curlx_malloc(sizeof(struct socketmonitor));
      if(m) {
        m->next = ev->list;
        m->socket.fd = s;
        m->socket.events = socketcb2poll(what);
        m->socket.revents = 0;
        ev->list = m;
        infof(data, "socket cb: socket %" FMT_SOCKET_T " ADDED as %s%s", s,
              (what & CURL_POLL_IN) ? "IN" : "",
              (what & CURL_POLL_OUT) ? "OUT" : "");
      }
      else
        return CURLE_OUT_OF_MEMORY;
    }
  }

  return 0;
}

/**
 * @internal
 * @brief Install the timer and socket callbacks on the multi handle.
 *
 * Do the multi handle setups that only event-based transfers need.
 *
 * @param[in,out] multi  The multi handle to configure.
 * @param[in]     ev     Event state passed as callback user data.
 */
static void events_setup(struct Curl_multi *multi, struct events *ev)
{
  /* timer callback */
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, events_timer);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, ev);

  /* socket callback */
  curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, events_socket);
  curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, ev);
}

/**
 * @internal
 * @brief Rebuild the poll descriptor set from the monitored sockets.
 *
 * @param[in,out] cpfds  Poll set, reset and refilled.
 * @param[in]     ev     Event state with the socket list.
 *
 * @return CURLE_OK on success, else the error from adding a socket.
 */
static CURLcode populate_cpfds(struct curl_pollfds *cpfds, struct events *ev)
{
  struct socketmonitor *m;
  CURLcode result = CURLE_OK;

  Curl_pollfds_reset(cpfds);
  for(m = ev->list; m && !result; m = m->next) {
    result = Curl_pollfds_add_sock(cpfds, m->socket.fd, m->socket.events);
#if DEBUG_EV_POLL
    if(!result)
      curl_mfprintf(stderr, "poll() %d check socket %d\n",
                    cpfds->n - 1, cpfds->pfds[cpfds->n - 1].fd);
#endif
  }
  return result;
}

/**
 * @internal
 * @brief Wait for socket activity or the current timeout.
 *
 * With no sockets to watch, simply sleeps for the timeout.
 *
 * @param[in]  ev      Event state with the timeout.
 * @param[in]  cpfds   Descriptors to poll.
 * @param[out] pollrc  Result of poll(): number of ready sockets, 0 on
 *                     timeout.
 *
 * @return CURLE_OK on success.
 * @return CURLE_UNRECOVERABLE_POLL if poll() failed.
 */
static CURLcode poll_cpfds(struct events *ev,
                           struct curl_pollfds *cpfds,
                           int *pollrc)
{
  if(cpfds->n) {
    /* wait for activity or timeout */
#if DEBUG_EV_POLL
    curl_mfprintf(stderr, "poll(numfds=%u, timeout=%ldms)\n",
                  cpfds->n, ev->ms);
#endif
    *pollrc = Curl_poll(cpfds->pfds, cpfds->n, ev->ms);
#if DEBUG_EV_POLL
    curl_mfprintf(stderr, "poll(numfds=%u, timeout=%ldms) -> %d\n",
                  cpfds->n, ev->ms, *pollrc);
#endif
    if(*pollrc < 0)
      return CURLE_UNRECOVERABLE_POLL;
  }
  else {
#if DEBUG_EV_POLL
    curl_mfprintf(stderr, "poll, but no fds, wait timeout=%ldms\n", ev->ms);
#endif
    *pollrc = 0;
    if(ev->ms > 0)
      curlx_wait_ms(ev->ms);
  }
  return CURLE_OK;
}

/**
 * @internal
 * @brief Drive the multi handle until a transfer completes.
 *
 * Waits for activity on any of the given sockets, or the timeout to
 * trigger, and feeds the outcome to curl_multi_socket_action(). The
 * timeout is decreased by the time spent unless a callback updated it.
 *
 * @param[in,out] multi  The multi handle with one transfer.
 * @param[in,out] ev     Event state.
 *
 * @return The CURLcode of the finished transfer.
 * @return CURLE_URL_MALFORMAT if curl_multi_socket_action() failed.
 * @return CURLE_UNRECOVERABLE_POLL or out of memory style errors from
 *         the polling helpers.
 */
static CURLcode wait_or_timeout(struct Curl_multi *multi, struct events *ev)
{
  struct pollfd fds_on_stack[8];
  struct curl_pollfds cpfds;
  bool done = FALSE;
  CURLMcode mresult = CURLM_OK;
  CURLcode result = CURLE_OK;

  Curl_pollfds_init(&cpfds, fds_on_stack, CURL_ARRAYSIZE(fds_on_stack));
  while(!done) {
    CURLMsg *msg;
    int pollrc;
    struct curltime start;

    result = populate_cpfds(&cpfds, ev);
    if(result)
      goto out;

    /* get the time stamp to use to figure out how long poll takes */
    curlx_pnow(&start);

    result = poll_cpfds(ev, &cpfds, &pollrc);
    if(result)
      goto out;

    ev->msbump = FALSE; /* reset here */

    if(!pollrc) {
      /* timeout! */
      ev->ms = 0;
#if DEBUG_EV_POLL
      curl_mfprintf(stderr, "call curl_multi_socket_action(TIMEOUT)\n");
#endif
      mresult = curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0,
                                         &ev->running_handles);
    }
    else {
      /* here pollrc is > 0 */
      /* loop over the monitored sockets to see which ones had activity */
      unsigned int i;
      for(i = 0; i < cpfds.n; i++) {
        if(cpfds.pfds[i].revents) {
          /* socket activity, tell libcurl */
          int act = poll2cselect(cpfds.pfds[i].revents); /* convert */

          /* sending infof "randomly" to the first easy handle */
          infof(multi->admin, "call curl_multi_socket_action(socket "
                "%" FMT_SOCKET_T ")", (curl_socket_t)cpfds.pfds[i].fd);
          mresult = curl_multi_socket_action(multi, cpfds.pfds[i].fd, act,
                                             &ev->running_handles);
        }
      }

      if(!ev->msbump && ev->ms >= 0) {
        /* If nothing updated the timeout, we decrease it by the spent time.
         * If it was updated, it has the new timeout time stored already.
         */
        timediff_t spent_ms = curlx_timediff_ms(curlx_now(), start);
        if(spent_ms > 0) {
#if DEBUG_EV_POLL
        curl_mfprintf(stderr, "poll timeout %ldms not updated, decrease by "
                      "time spent %ldms\n", ev->ms, (long)spent_ms);
#endif
          if(spent_ms > ev->ms)
            ev->ms = 0;
          else
            ev->ms -= (long)spent_ms;
        }
      }
    }

    if(mresult) {
      result = CURLE_URL_MALFORMAT;
      goto out;
    }

    /* we do not really care about the "msgs_in_queue" value returned in the
       second argument */
    msg = curl_multi_info_read(multi, &pollrc);
    if(msg) {
      result = msg->data.result;
      done = TRUE;
    }
  }
out:
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

/**
 * @internal
 * @brief Run a transfer in a blocking manner using the events-based API.
 *
 * @param[in,out] multi  The multi handle with one transfer.
 *
 * @return The CURLcode of the transfer, see wait_or_timeout().
 * @warning The event state is a function-local static so it outlives the
 *          call (needed while the handle is removed); thus this is not
 *          thread-safe.
 */
static CURLcode easy_events(struct Curl_multi *multi)
{
  /* this struct is made static to allow it to be used after this function
     returns and curl_multi_remove_handle() is called */
  static struct events evs = { -1, FALSE, 0, NULL, 0 };

  /* if running event-based, do some further multi inits */
  events_setup(multi, &evs);

  return wait_or_timeout(multi, &evs);
}
#else /* DEBUGBUILD */
/**
 * @internal
 * @brief Release builds: the event engine does not exist, so this macro
 *        evaluates to CURLE_NOT_BUILT_IN.
 */
#define easy_events(x) CURLE_NOT_BUILT_IN
#endif

/**
 * @internal
 * @brief Run a transfer to completion with curl_multi_poll()/perform().
 *
 * Loops, waiting up to one second per round, until the multi handle has
 * no running transfers and a completion message can be read.
 *
 * @param[in,out] multi  The multi handle with one transfer.
 *
 * @return The CURLcode of the finished transfer.
 * @return CURLE_OUT_OF_MEMORY if the multi interface ran out of memory.
 * @return CURLE_BAD_FUNCTION_ARGUMENT for any other multi error, which
 *         should never happen.
 */
static CURLcode easy_transfer(struct Curl_multi *multi)
{
  bool done = FALSE;
  CURLMcode mresult = CURLM_OK;
  CURLcode result = CURLE_OK;

  while(!done && !mresult) {
    int still_running = 0;

    mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(!mresult)
      mresult = curl_multi_perform(multi, &still_running);

    /* only read 'still_running' if curl_multi_perform() return OK */
    if(!mresult && !still_running) {
      int rc;
      CURLMsg *msg = curl_multi_info_read(multi, &rc);
      if(msg) {
        result = msg->data.result;
        done = TRUE;
      }
    }
  }

  /* Make sure to return some kind of error if there was a multi problem */
  if(mresult) {
    result = (mresult == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  return result;
}

/**
 * @internal
 * @brief Perform a blocking transfer as previously set up.
 *
 * easy_perform() is the internal interface that performs a blocking
 * transfer.
 *
 * CONCEPT: This function creates a multi handle, adds the easy handle to
 * it, runs curl_multi_perform() until the transfer is done, then detaches
 * the easy handle, destroys the multi handle and returns the easy
 * handle's return code.
 *
 * REALITY: it cannot create and destroy the multi handle that easily. It
 * needs to keep it around since if this easy handle is used again by this
 * function, the same multi handle must be reused so that the same pools
 * and caches can be used.
 *
 * DEBUG: if 'events' is set TRUE, this function will use a replacement
 * engine instead of curl_multi_perform() and use
 * curl_multi_socket_action().
 *
 * @param[in,out] data    The easy handle to run.
 * @param[in]     events  TRUE to use the event engine (debug builds only).
 *
 * @return CURLE_OK if the transfer succeeded.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p data is NULL.
 * @return CURLE_FAILED_INIT if the handle is already in a user multi
 *         handle, or adding it to the private multi handle failed.
 * @return CURLE_RECURSIVE_API_CALL if called from within a callback.
 * @return CURLE_OUT_OF_MEMORY if no multi handle could be created.
 * @return Any other CURLcode describing the transfer result.
 *
 * @note A leftover connect-only connection on the handle is closed first.
 * @warning The private multi handle is owned by the easy handle
 *          (@c data->multi_easy) and kept alive after returning.
 */
static CURLcode easy_perform(struct Curl_easy *data, bool events)
{
  struct Curl_multi *multi;
  CURLMcode mresult;
  CURLcode result = CURLE_OK;
  struct Curl_sigpipe_ctx sigpipe_ctx;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->set.errorbuffer)
    /* clear this as early as possible */
    data->set.errorbuffer[0] = 0;

  data->state.os_errno = 0;

  if(data->multi) {
    failf(data, "easy handle already used in multi handle");
    return CURLE_FAILED_INIT;
  }

  /* if the handle has a connection still attached (it is/was a connect-only
     handle) then disconnect before performing */
  if(data->conn) {
    struct connectdata *conn = data->conn;
    Curl_detach_connection(data);
    Curl_conn_close(data, conn, TRUE);
    DEBUGASSERT(!data->conn);
  }

  if(data->multi_easy)
    multi = data->multi_easy;
  else {
    /* this multi handle will only ever have a single easy handle attached to
       it, so make it use minimal hash sizes */
    multi = Curl_multi_handle(16, 1, 3, 7, 3);
    if(!multi)
      return CURLE_OUT_OF_MEMORY;
  }

  if(Curl_api_multi_is_in_callback(multi))
    return CURLE_RECURSIVE_API_CALL;

  /* Copy relevant easy options to the multi handle */
  curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, (long)data->set.maxconnects);
  curl_multi_setopt(multi, CURLMOPT_QUICK_EXIT, (long)data->set.quick_exit);

  data->multi_easy = NULL; /* pretend it does not exist */
  mresult = Curl_multi_add_handle(multi, data);
  if(mresult) {
    curl_multi_cleanup(multi);
    if(mresult == CURLM_OUT_OF_MEMORY)
      return CURLE_OUT_OF_MEMORY;
    return CURLE_FAILED_INIT;
  }

  /* assign this after curl_multi_add_handle() */
  data->multi_easy = multi;

  sigpipe_init(&sigpipe_ctx);
  sigpipe_apply(data, &sigpipe_ctx);

  /* run the transfer */
  result = events ? easy_events(multi) : easy_transfer(multi);

  /* ignoring the return code is not nice, but atm we cannot really handle
     a failure here, room for future improvement! */
  (void)Curl_multi_remove_handle(multi, data);

  sigpipe_restore(&sigpipe_ctx);

  /* The multi handle is kept alive, owned by the easy handle */
  return result;
}

/**
 * @brief Perform a blocking file transfer.
 *
 * curl_easy_perform() is the external interface that performs a blocking
 * transfer as previously setup.
 *
 * @param[in] curl  Easy handle from curl_easy_init().
 *
 * @return CURLE_OK on success, otherwise a CURLcode describing the error
 *         (see easy_perform() for the handle related ones).
 * @return CURLE_BAD_FUNCTION_ARGUMENT for an invalid handle.
 *
 * @warning Must not be called from within a libcurl callback or with a
 *          handle that is added to a multi handle.
 * @see curl_easy_init(), curl_multi_perform()
 */
CURLcode curl_easy_perform(CURL *curl)
{
  struct Curl_eapi_guard guard = { 0 };
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_perform, &result)) {
    result = easy_perform(curl, FALSE);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}

#ifdef DEBUGBUILD
/**
 * @internal
 * @brief Debug builds: perform a blocking transfer using the event-based
 *        API internally.
 *
 * curl_easy_perform_ev() is the external interface that performs a
 * blocking transfer using curl_multi_socket_action() instead of
 * curl_multi_perform().
 *
 * @param[in] easy  Easy handle from curl_easy_init().
 *
 * @return Same values as curl_easy_perform().
 */
CURLcode curl_easy_perform_ev(struct Curl_easy *easy)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, easy, easy_perform_ev, &result)) {
    result = easy_perform(easy, TRUE);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}
#endif

/**
 * @brief Clean up and free an easy handle.
 *
 * curl_easy_cleanup() is the external interface to cleaning/freeing the
 * given easy handle. SIGPIPE is ignored while connections are closed.
 *
 * @param[in] curl  Easy handle to free; NULL or invalid handles are
 *                  ignored.
 *
 * @warning The handle must not be used afterwards. It must not be freed
 *          from within a callback or while it is in a multi handle.
 * @see curl_easy_init()
 */
void curl_easy_cleanup(CURL *curl)
{
  struct Curl_eapi_guard guard;

  if(CURL_EAPI_ENTER(&guard, curl, easy_cleanup, NULL)) {
    struct Curl_easy *data = curl;
    struct Curl_sigpipe_ctx sigpipe_ctx;
    sigpipe_ignore(data, &sigpipe_ctx);
    Curl_close(&data);
    sigpipe_restore(&sigpipe_ctx);
  }
  CURL_EAPI_LEAVE(&guard);
}

/**
 * @brief Retrieve information about a performed transfer.
 *
 * curl_easy_getinfo() is an external interface that allows an app to
 * retrieve information from a performed transfer and similar.
 *
 * @param[in]  curl  Easy handle.
 * @param[in]  info  The CURLINFO_* item to get.
 * @param[out] ...   Exactly one pointer whose type depends on @p info.
 *
 * @return CURLE_OK on success.
 * @return CURLE_UNKNOWN_OPTION if @p info is not known.
 * @return CURLE_BAD_FUNCTION_ARGUMENT for an invalid handle.
 *
 * @warning Returned string pointers are owned by the handle and only
 *          valid until the next transfer or until it is cleaned up.
 */
#undef curl_easy_getinfo
CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_getinfo, &result)) {
    struct Curl_easy *data = curl;
    va_list arg;
    void *paramp;

    va_start(arg, info);
    paramp = va_arg(arg, void *);

    result = Curl_getinfo(data, info, paramp);

    va_end(arg);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}

/**
 * @internal
 * @brief Duplicate the user-set options of an easy handle.
 *
 * Copies @c src->set into @c dst->set, then deep copies the strings,
 * blobs, the copied POST fields and the MIME structure so that both
 * handles own separate memory.
 *
 * @param[in,out] dst  Destination handle; its set struct is overwritten.
 * @param[in]     src  Source handle.
 *
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY if any copy failed.
 * @return Other CURLcode from duplicating strings, blobs or MIME parts.
 *
 * @note On failure the destination is left in a state that the caller
 *       can free with Curl_freeset().
 */
static CURLcode dupset(struct Curl_easy *dst, struct Curl_easy *src)
{
  CURLcode result = CURLE_OK;
  enum dupblob j;

  /* Copy src->set into dst->set first, then deal with the strings
     afterwards */
  dst->set = src->set;
#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  dst->set.mimepostp = NULL;
#endif
  dst->set.str_copypostfields = NULL;

  Curl_u8_strset_init(&dst->set.strings);
  /* clear all dest string and blob pointers first, in case we error out
     mid-function */
  memset(dst->set.blobs, 0, BLOB_LAST * sizeof(struct curl_blob *));

  /* duplicate all strings */
  result = Curl_u8_strset_copy(&dst->set.strings, &src->set.strings);
  if(result)
    return result;

  /* duplicate all blobs */
  for(j = (enum dupblob)0; j < BLOB_LAST; j++) {
    result = Curl_setblobopt(&dst->set.blobs[j], src->set.blobs[j]);
    if(result)
      return result;
  }

  /* duplicate memory areas pointed to */
  if(src->set.str_copypostfields) {
    if(src->set.postfieldsize == -1)
      dst->set.str_copypostfields = curlx_strdup(src->set.str_copypostfields);
    else
      /* postfieldsize is curl_off_t, curlx_memdup0() takes a size_t ... */
      dst->set.str_copypostfields =
        curlx_memdup0(src->set.str_copypostfields,
                      curlx_sotouz(src->set.postfieldsize));
    if(!dst->set.str_copypostfields)
      return CURLE_OUT_OF_MEMORY;
    /* point to the new copy */
    dst->set.postfields = dst->set.str_copypostfields;
  }

#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  if(src->set.mimepostp) {
    /* Duplicate mime data. Get a mimepost struct for the clone as well */
    dst->set.mimepostp = curlx_malloc(sizeof(*dst->set.mimepostp));
    if(!dst->set.mimepostp)
      return CURLE_OUT_OF_MEMORY;

    Curl_mime_initpart(dst->set.mimepostp);
    result = Curl_mime_duppart(dst, dst->set.mimepostp, src->set.mimepostp);
    if(result)
      return result;
  }
#endif

  if(src->set.resolve)
    dst->state.resolve = dst->set.resolve;

  return result;
}

/**
 * @internal
 * @brief Destructor installed for the meta hash of a duplicated handle.
 *
 * The new handle's meta hash is empty, so this must never be called.
 *
 * @param[in] p  Hash entry, always NULL.
 */
static void dupeasy_meta_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(!p);
}

/**
 * @brief Duplicate an easy handle.
 *
 * curl_easy_duphandle() is an external interface to allow duplication of a
 * given input easy handle. The returned handle will be a new working
 * handle with all options set exactly as the input source handle.
 * Cookies, alt-svc and HSTS caches are duplicated when enabled, as are
 * the URL and referer.
 *
 * @param[in] curl  The easy handle to copy.
 *
 * @return A new easy handle, to be released with curl_easy_cleanup().
 * @return NULL on failure or for an invalid handle.
 *
 * @note Live connections, the DNS cache and other transfer state are not
 *       copied.
 * @warning Pointers given with CURLOPT_*DATA options are copied as is, so
 *          both handles share the pointed-to data.
 */
CURL *curl_easy_duphandle(CURL *curl)
{
  struct Curl_eapi_guard guard;
  struct Curl_easy *outcurl = NULL;

  if(CURL_EAPI_ENTER(&guard, curl, easy_duphandle, NULL)) {
    struct Curl_easy *data = curl;

    outcurl = curlx_calloc(1, sizeof(struct Curl_easy));
    if(!outcurl)
      goto fail;

    /*
     * We setup a few buffers we need. We should probably make them
     * get setup on-demand in the code, as that would probably decrease
     * the likeliness of us forgetting to init a buffer here in the future.
     */
    outcurl->set.buffer_size = data->set.buffer_size;

    Curl_hash_init(&outcurl->meta_hash, 23, CURL_HASH_TYPE_BYTES,
                   dupeasy_meta_freeentry);
    curlx_dyn_init(&outcurl->state.headerb, CURL_MAX_HTTP_HEADER);
    Curl_bufref_init(&outcurl->state.url);
    Curl_bufref_init(&outcurl->state.referer);
    Curl_netrc_init(&outcurl->state.netrc);

    /* the connection pool is setup on demand */
    outcurl->state.last_conn_id = -1;
    outcurl->state.last_cpid = UINT32_MAX;
    outcurl->id = -1;
    outcurl->mid = UINT32_MAX;
    outcurl->master_mid = UINT32_MAX;

#ifndef CURL_DISABLE_HTTP
    Curl_llist_init(&outcurl->state.httphdrs, NULL);
#endif
    Curl_initinfo(outcurl);

    /* copy all userdefined values */
    if(dupset(outcurl, data))
      goto fail;

    outcurl->progress.hide     = data->progress.hide;
    outcurl->progress.callback = data->progress.callback;

#ifndef CURL_DISABLE_COOKIES
    outcurl->state.cookielist = NULL;
    if(data->cookies && data->state.cookie_engine) {
      /* If cookies are enabled in the parent handle, we enable them
         in the clone as well! */
      outcurl->cookies = Curl_cookie_init();
      if(!outcurl->cookies)
        goto fail;
      outcurl->state.cookie_engine = TRUE;
    }

    if(data->state.cookielist) {
      outcurl->state.cookielist = Curl_slist_duplicate(data->state.cookielist);
      if(!outcurl->state.cookielist)
        goto fail;
    }
#endif

    if(Curl_bufref_ptr(&data->state.url)) {
      Curl_bufref_set(&outcurl->state.url,
                      Curl_bufref_dup(&data->state.url), 0,
                      curl_free);
      if(!Curl_bufref_ptr(&outcurl->state.url))
        goto fail;
    }
    if(Curl_bufref_ptr(&data->state.referer)) {
      Curl_bufref_set(&outcurl->state.referer,
                      Curl_bufref_dup(&data->state.referer), 0,
                      curl_free);
      if(!Curl_bufref_ptr(&outcurl->state.referer))
        goto fail;
    }

#ifndef CURL_DISABLE_ALTSVC
    if(data->asi) {
      const char *str;
      outcurl->asi = Curl_altsvc_init();
      if(!outcurl->asi)
        goto fail;
      str = CURL_EASY_STR(outcurl, STRING_ALTSVC);
      if(str)
        (void)Curl_altsvc_load(outcurl->asi, str);
    }
#endif
#ifndef CURL_DISABLE_HSTS
    if(data->hsts) {
      const char *str;
      outcurl->hsts = Curl_hsts_init();
      if(!outcurl->hsts)
        goto fail;
      str = CURL_EASY_STR(outcurl, STRING_HSTS);
      if(str)
        (void)Curl_hsts_loadfile(outcurl, outcurl->hsts, str);
      (void)Curl_hsts_loadcb(outcurl, outcurl->hsts);

      /* Copy entries learned at runtime. (E.g. Strict-Transport-Security
         headers.) */
      if(Curl_hsts_copy(outcurl->hsts, data->hsts))
        goto fail;
    }
#endif

    /* we reach this point and thus we are OK */
    outcurl->magic = CURLEASY_MAGIC_NUMBER;
  }
  CURL_EAPI_LEAVE(&guard);
  return outcurl;

fail:
  if(outcurl) {
#ifndef CURL_DISABLE_COOKIES
    curlx_free(outcurl->cookies);
#endif
    curlx_dyn_free(&outcurl->state.headerb);
    Curl_altsvc_cleanup(&outcurl->asi);
    Curl_hsts_cleanup(&outcurl->hsts);
    Curl_freeset(outcurl);
    curlx_free(outcurl);
  }

  CURL_EAPI_LEAVE(&guard);
  return NULL;
}

/**
 * @brief Reset an easy handle to its initial option values.
 *
 * curl_easy_reset() is an external interface that allows an app to
 * re-initialize a session handle to the default values. Options, progress
 * data, info data and authentication state are cleared; live connections,
 * caches and the session ID cache are kept.
 *
 * @param[in,out] curl  The easy handle to reset.
 *
 * @warning Not allowed while the handle is being used by a transfer in
 *          another thread.
 */
void curl_easy_reset(CURL *curl)
{
  struct Curl_eapi_guard guard;

  if(CURL_EAPI_ENTER(&guard, curl, easy_reset, NULL)) {
    struct Curl_easy *data = curl;

    data->state.last_conn_id = -1; /* clear remembered connection id */
    data->state.last_cpid = UINT32_MAX;
    Curl_req_hard_reset(&data->req, data);
    Curl_hash_clean(&data->meta_hash);

    /* clear all meta data */
    Curl_meta_reset(data);
    /* zero out UserDefined data: */
    Curl_freeset(data);
    memset(&data->set, 0, sizeof(struct UserDefined));
    Curl_init_userdefined(data);
    data->state.resolve = NULL;

    /* zero out Progress data: */
    memset(&data->progress, 0, sizeof(struct Progress));

    /* zero out PureInfo data: */
    Curl_initinfo(data);

    data->progress.hide = TRUE;

    /* zero out authentication data: */
    memset(&data->state.authhost, 0, sizeof(struct auth));
    memset(&data->state.authproxy, 0, sizeof(struct auth));

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_DIGEST_AUTH)
    Curl_http_auth_cleanup_digest(data);
#endif
    data->master_mid = UINT32_MAX;
  }
  CURL_EAPI_LEAVE(&guard);
}

/**
 * @brief Pause or unpause a transfer in either direction.
 *
 * curl_easy_pause() allows an application to pause or unpause a specific
 * transfer and direction. This function sets the full new state for the
 * current connection this easy handle operates on.
 *
 * @param[in] curl    The easy handle.
 * @param[in] action  Bitmask of CURLPAUSE_* bits in curl/curl.h.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if the handle has no connection.
 * @return CURLE_ABORTED_BY_CALLBACK if the application timer or socket
 *         callback signalled an error after the state changed.
 * @return Other CURLcode from pausing/unpausing the send or receive side.
 *
 * @note If you have the receiving paused and you call this function to
 *       remove the pausing, you may get your write callback called at
 *       this point.
 * @note This is one of few API functions that are allowed to be called
 *       from within a callback.
 */
CURLcode curl_easy_pause(CURL *curl, int action)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, easy_pause, &result)) {
    bool changed = FALSE;
    struct Curl_easy *data = curl;
    bool recv_paused, recv_paused_new;
    bool send_paused, send_paused_new;

    if(!data->conn) {
      /* crazy input, do not continue */
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    recv_paused = Curl_xfer_recv_is_paused(data);
    recv_paused_new = (action & CURLPAUSE_RECV);
    send_paused = Curl_xfer_send_is_paused(data);
    send_paused_new = (action & CURLPAUSE_SEND);

    if((send_paused != send_paused_new) ||
       (send_paused_new != Curl_creader_is_paused(data))) {
      changed = TRUE;
      result = Curl_1st_fatal(
        result, Curl_xfer_pause_send(data, send_paused_new));
    }

    if(recv_paused != recv_paused_new) {
      changed = TRUE;
      result = Curl_1st_fatal(
        result, Curl_xfer_pause_recv(data, recv_paused_new));
    }

    /* If not completely pausing both directions, run again in any case. */
    if(!Curl_xfer_is_blocked(data)) {
      /* reset the too-slow time keeper */
      data->state.keeps_speed.tv_sec = 0;
      if(data->multi) {
        Curl_multi_mark_dirty(data); /* make it run */
        /* On changes, tell application to update its timers. */
        if(changed && Curl_update_timer(data->multi) && !result)
          result = CURLE_ABORTED_BY_CALLBACK;
      }
    }

    if(!result && changed && !data->state.done && data->multi &&
       /* pause/unpausing may result in multi event changes */
       Curl_multi_ev_assess_xfer(data->multi, data))
      result = CURLE_ABORTED_BY_CALLBACK;
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

/**
 * @internal
 * @brief Find the connection of a connect-only handle.
 *
 * @param[in]  data   The easy handle.
 * @param[out] connp  Receives the connection used last.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p data is NULL.
 * @return CURLE_UNSUPPORTED_PROTOCOL if CURLOPT_CONNECT_ONLY is not set
 *         or the last connection socket cannot be found.
 */
static CURLcode easy_connection(struct Curl_easy *data,
                                struct connectdata **connp)
{
  curl_socket_t sfd;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* only allow these to be called on handles with CURLOPT_CONNECT_ONLY */
  if(!data->set.connect_only) {
    failf(data, "CONNECT_ONLY is required");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  sfd = Curl_getconnectinfo(data, connp);

  if(sfd == CURL_SOCKET_BAD) {
    failf(data, "Failed to get last socket used for connection #%" FMT_OFF_T,
          data->state.last_conn_id);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  return CURLE_OK;
}

/**
 * @brief Receive data from the connected socket.
 *
 * Use after successful curl_easy_perform() with the CURLOPT_CONNECT_ONLY
 * option. On the first call the transfer is reattached to its connection.
 *
 * @param[in]  data    The easy handle.
 * @param[out] buffer  Buffer to receive into.
 * @param[in]  buflen  Size of @p buffer.
 * @param[out] n       Number of bytes received.
 *
 * @return CURLE_OK on success.
 * @return CURLE_AGAIN if no data is available right now.
 * @return CURLE_UNSUPPORTED_PROTOCOL if not a connect-only handle.
 * @return Other CURLcode errors from the connection.
 */
CURLcode Curl_easy_recv(struct Curl_easy *data,
                        void *buffer, size_t buflen, size_t *n)
{
  CURLcode result;
  struct connectdata *c;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c, TRUE);

  *n = 0;
  return Curl_conn_recv(data, FIRSTSOCKET, buffer, buflen, n);
}

/**
 * @brief Public API: receive raw data on a connect-only connection.
 *
 * @param[in]  curl    The easy handle.
 * @param[out] buffer  Buffer to receive into.
 * @param[in]  buflen  Size of @p buffer.
 * @param[out] n       Number of bytes received.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p n is NULL or @p buffer is NULL
 *         with a non-zero length.
 * @return See Curl_easy_recv() for the other values.
 * @see curl_easy_send()
 */
CURLcode curl_easy_recv(CURL *curl, void *buffer, size_t buflen, size_t *n)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_recv, &result)) {
    if(!n || (buflen && !buffer)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    result = Curl_easy_recv(curl, buffer, buflen, n);
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

#ifndef CURL_DISABLE_WEBSOCKETS
/**
 * @internal
 * @brief Attach a connect-only handle to its connection if detached.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK on success.
 * @return CURLE_UNSUPPORTED_PROTOCOL if not a connect-only handle or the
 *         connection is gone.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p data is NULL.
 */
CURLcode Curl_connect_only_attach(struct Curl_easy *data)
{
  CURLcode result;
  struct connectdata *c = NULL;

  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c, TRUE);

  return CURLE_OK;
}
#endif /* !CURL_DISABLE_WEBSOCKETS */

/**
 * @internal
 * @brief Send data over the connected socket.
 *
 * This is the private internal version of curl_easy_send(). SIGPIPE is
 * suppressed during the send.
 *
 * @param[in,out] data    The easy handle.
 * @param[in]     buffer  Data to send.
 * @param[in]     buflen  Length of @p buffer.
 * @param[out]    n       Number of bytes sent.
 *
 * @return CURLE_OK on success.
 * @return CURLE_AGAIN if the socket is not ready for writing.
 * @return CURLE_SEND_ERROR for any other send failure.
 * @return CURLE_UNSUPPORTED_PROTOCOL if not a connect-only handle.
 */
CURLcode Curl_senddata(struct Curl_easy *data, const void *buffer,
                       size_t buflen, size_t *n)
{
  CURLcode result;
  struct connectdata *c = NULL;
  struct Curl_sigpipe_ctx sigpipe_ctx;

  *n = 0;
  result = easy_connection(data, &c);
  if(result)
    return result;

  if(!data->conn)
    /* on first invoke, the transfer has been detached from the connection and
       needs to be reattached */
    Curl_attach_connection(data, c, TRUE);

  sigpipe_ignore(data, &sigpipe_ctx);
  result = Curl_conn_send(data, FIRSTSOCKET, buffer, buflen, FALSE, n);
  sigpipe_restore(&sigpipe_ctx);

  if(result && result != CURLE_AGAIN)
    return CURLE_SEND_ERROR;
  return result;
}

/**
 * @brief Send raw data over the connected socket.
 *
 * Use after successful curl_easy_perform() with the CURLOPT_CONNECT_ONLY
 * option.
 *
 * @param[in]  curl    The easy handle.
 * @param[in]  buffer  Data to send.
 * @param[in]  buflen  Length of @p buffer.
 * @param[out] n       Number of bytes sent.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p n is NULL or @p buffer is NULL
 *         with a non-zero length.
 * @return CURLE_AGAIN, CURLE_SEND_ERROR or CURLE_UNSUPPORTED_PROTOCOL as
 *         described for Curl_senddata().
 * @see curl_easy_recv()
 */
CURLcode curl_easy_send(CURL *curl, const void *buffer, size_t buflen,
                        size_t *n)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_send, &result)) {
    struct Curl_easy *data = curl;
    size_t written = 0;

    if(!n || (buflen && !buffer)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    result = Curl_senddata(data, buffer, buflen, &written);
    *n = written;
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

/**
 * @brief Perform connection upkeep for the given session handle.
 *
 * Gives the connection pool a chance to keep connections alive, for
 * example by sending HTTP/2 PING frames.
 *
 * @param[in] curl  The easy handle.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT for an invalid handle.
 * @return Other CURLcode errors from the upkeep operations.
 */
CURLcode curl_easy_upkeep(CURL *curl)
{
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_upkeep, &result)) {
    /* Use the common function to keep connections alive. */
    result = Curl_cpool_upkeep((struct Curl_easy *)curl);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
}

/**
 * @brief Import a serialized TLS session into the session cache.
 *
 * @param[in] curl         The easy handle.
 * @param[in] session_key  Cache key, or NULL to use the exported one.
 * @param[in] shmac        HMAC of the session key data.
 * @param[in] shmac_len    Length of @p shmac.
 * @param[in] sdata        Serialized session data, must not be empty.
 * @param[in] sdata_len    Length of @p sdata.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if the session data is missing.
 * @return CURLE_NOT_BUILT_IN if TLS session export is not supported by
 *         this build.
 * @return Other CURLcode from the import itself.
 */
CURLcode curl_easy_ssls_import(CURL *curl, const char *session_key,
                               const unsigned char *shmac, size_t shmac_len,
                               const unsigned char *sdata, size_t sdata_len)
{
#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_ssls_import, &result)) {
    if(!sdata || !sdata_len)
      result = CURLE_BAD_FUNCTION_ARGUMENT;
    else
      result = Curl_ssl_session_import((struct Curl_easy *)curl, session_key,
                                       shmac, shmac_len, sdata, sdata_len);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
#else
  (void)curl;
  (void)session_key;
  (void)shmac;
  (void)shmac_len;
  (void)sdata;
  (void)sdata_len;
  return CURLE_NOT_BUILT_IN;
#endif
}

/**
 * @brief Export the cached TLS sessions through a callback.
 *
 * @param[in] curl       The easy handle.
 * @param[in] export_fn  Callback invoked per session, must not be NULL.
 * @param[in] userptr    Opaque pointer passed to @p export_fn.
 *
 * @return CURLE_OK on success.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if @p export_fn is NULL.
 * @return CURLE_NOT_BUILT_IN if TLS session export is not supported by
 *         this build.
 * @return Other CURLcode, including errors returned by @p export_fn.
 */
CURLcode curl_easy_ssls_export(CURL *curl,
                               curl_ssls_export_cb *export_fn,
                               void *userptr)
{
#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)
  struct Curl_eapi_guard guard;
  CURLcode result;

  if(CURL_EAPI_ENTER(&guard, curl, easy_ssls_export, &result)) {
    if(!export_fn)
      result = CURLE_BAD_FUNCTION_ARGUMENT;
    else
      result = Curl_ssl_session_export((struct Curl_easy *)curl,
                                       export_fn, userptr);
  }
  CURL_EAPI_LEAVE(&guard);
  return result;
#else
  (void)curl;
  (void)export_fn;
  (void)userptr;
  return CURLE_NOT_BUILT_IN;
#endif
}

/**
 * @brief Attach meta data to the easy handle under a key.
 *
 * The meta data is owned by the handle afterwards and freed with the
 * given destructor when removed, replaced or when the handle goes away.
 *
 * @param[in,out] data       The easy handle.
 * @param[in]     key        NUL-terminated key, copied by the hash.
 * @param[in]     meta_data  The data, must not be NULL.
 * @param[in]     meta_dtor  Destructor called on the data.
 *
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY if it could not be stored; the destructor
 *         has then already been called on @p meta_data.
 */
CURLcode Curl_meta_set(struct Curl_easy *data, const char *key,
                       void *meta_data, Curl_meta_dtor *meta_dtor)
{
  DEBUGASSERT(meta_data); /* never set to NULL */
  if(!Curl_hash_add2(&data->meta_hash, key, strlen(key) + 1,
                     meta_data, meta_dtor)) {
    meta_dtor(key, strlen(key) + 1, meta_data);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

/**
 * @brief Remove (and destroy) the meta data stored under a key.
 *
 * @param[in,out] data  The easy handle.
 * @param[in]     key   NUL-terminated key; a missing key is ignored.
 */
void Curl_meta_remove(struct Curl_easy *data, const char *key)
{
  Curl_hash_delete(&data->meta_hash, key, strlen(key) + 1);
}

/**
 * @brief Look up meta data stored under a key.
 *
 * @param[in] data  The easy handle.
 * @param[in] key   NUL-terminated key.
 *
 * @return The stored pointer, or NULL if there is none.
 * @warning The data stays owned by the handle.
 */
void *Curl_meta_get(struct Curl_easy *data, const char *key)
{
  return Curl_hash_pick(&data->meta_hash, key, strlen(key) + 1);
}

void Curl_meta_reset(struct Curl_easy *data)
{
  Curl_hash_clean(&data->meta_hash);
}

/** @} */
