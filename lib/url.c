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
 * @brief URL handling and connection setup for transfers.
 *
 * This file hosts the glue between a Curl_easy handle and the connection it
 * uses: parsing the transfer URL into an origin and credentials, creating a
 * template ("needle") connection, matching it against the connection pool for
 * reuse, and finally attaching an existing or new connection to the transfer.
 * It also contains Curl_open()/Curl_close() (handle life cycle), the default
 * option values (Curl_init_userdefined()) and small helpers such as per
 * connection metadata storage.
 *
 * @note Everything named url_* or *_internals is private to this file.
 * @see urlapi.c for the CURLU URL parser, conncache.c for the pool.
 *
 * @defgroup url_conn_reuse Connection reuse matching
 * @brief The url_match_* predicates deciding if a pooled connection fits.
 * @internal
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
#ifdef HAVE_IPHLPAPI_H
#include <Iphlpapi.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifndef HAVE_SOCKET
#error "We cannot compile without socket() support"
#endif

#if defined(HAVE_IF_NAMETOINDEX) && defined(USE_WINSOCK)
#if defined(__MINGW32__) && (__MINGW64_VERSION_MAJOR <= 5)
#include <wincrypt.h>  /* workaround for old mingw-w64 missing to include it */
#endif
#include <iphlpapi.h>
#endif

#include "urldata.h"
#include "mime.h"
#include "bufref.h"
#include "vtls/vtls.h"
#include "vssh/vssh.h"
#include "transfer.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "progress.h"
#include "cookie.h"
#include "strcase.h"
#include "escape.h"
#include "curl_share.h"
#include "http_digest.h"
#include "multiif.h"
#include "getinfo.h"
#include "pop3.h"
#include "urlapi-int.h"
#include "hsts.h"
#include "proxy.h"
#include "cfilters.h"
#include "idn.h"
#include "http_proxy.h"
#include "conncache.h"
#include "multihandle.h"
#include "curlx/strdup.h"
#include "setopt.h"
#include "altsvc.h"
#include "curlx/dynbuf.h"
#include "headers.h"
#include "curlx/strerr.h"
#include "curlx/strparse.h"
#include "peer.h"

/* Now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "tftp.h"
#include "http.h"
#include "vauth/vauth.h"
#include "file.h"
#include "curl_ldap.h"
#include "vssh/ssh.h"
#include "imap.h"
#include "url.h"
#include "connect.h"
#include "gopher.h"
#include "mqtt.h"
#include "rtsp.h"
#include "smtp.h"
#include "ws.h"

/* Some parts of the code (e.g. chunked encoding) assume this buffer has more
 * than a few bytes to play with. Do not let it become too small or bad things
 * will happen.
 */
/**
 * @brief Compile time sanity check of the receive buffer size.
 *
 * Code such as the chunked decoder assumes the buffer holds more than a few
 * bytes. Building with a too small READBUFFER_SIZE is rejected here.
 */
#if READBUFFER_SIZE < READBUFFER_MIN
# error READBUFFER_SIZE is too small
#endif

/**
 * @brief Return the protocol family of a scheme.
 * @internal
 *
 * Gives the family as a single bit protocol identifier, used to decide if
 * two different schemes (e.g. imap and imaps) belong together.
 *
 * @param[in] s  scheme to query, must not be NULL and have a family set.
 * @return the family bit of the scheme (never 0).
 * @pre @p s != NULL and @p s->family != 0 (checked by DEBUGASSERT).
 */
static curl_prot_t get_protocol_family(const struct Curl_scheme *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->family);
  return s->family;
}

/**
 * @brief Free all dynamic data stored in the "set" part of a handle.
 *
 * Releases the password-like strings (cleared securely), the generic string
 * set, copied POST fields, blobs, referer and URL buffers, the mime post
 * structure and the cookie list set via options.
 *
 * @param[in,out] data  transfer handle whose data->set members get released.
 * @note Pointers are reset to NULL, so calling it again is harmless.
 * @warning Does not free data itself nor stdio streams in data->set.
 * @see Curl_init_userdefined(), Curl_close()
 */
void Curl_freeset(struct Curl_easy *data)
{
  /* Free all dynamic strings stored in the data->set substructure. */
  enum dupblob j;

  CURL_EASY_STR_CLEAR0(data, STRING_PASSWORD);
  CURL_EASY_STR_CLEAR0(data, STRING_KEY_PASSWD);
  CURL_EASY_STR_CLEAR0(data, STRING_BEARER);
#ifndef CURL_DISABLE_PROXY
  CURL_EASY_STR_CLEAR0(data, STRING_PROXYPASSWORD);
  CURL_EASY_STR_CLEAR0(data, STRING_KEY_PASSWD_PROXY);
#endif
  Curl_u8_strset_clear(&data->set.strings);
  curlx_safefree(data->set.str_copypostfields);

  for(j = (enum dupblob)0; j < BLOB_LAST; j++) {
    curlx_safefree(data->set.blobs[j]);
  }

  Curl_bufref_free(&data->state.referer);
  Curl_bufref_free(&data->state.url);

#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  Curl_mime_cleanpart(data->set.mimepostp);
  curlx_safefree(data->set.mimepostp);
#endif

#ifndef CURL_DISABLE_COOKIES
  curl_slist_free_all(data->state.cookielist);
  data->state.cookielist = NULL;
#endif
}

/**
 * @brief Free the URL pieces held by the transfer.
 * @internal
 *
 * Releases the cached options, path and query strings and the CURLU handle
 * in data->state.
 *
 * @param[in,out] data  transfer handle, state.up and state.uh are reset.
 * @post data->state.uh == NULL and all urlpieces members are NULL.
 */
static void up_free(struct Curl_easy *data)
{
  struct urlpieces *up = &data->state.up;
  curlx_safefree(up->options);
  curlx_safefree(up->path);
  curlx_safefree(up->query);
  curl_url_cleanup(data->state.uh);
  data->state.uh = NULL;
}

/**
 * @brief Destroy a transfer handle and free all its resources.
 *
 * This is the internal function curl_easy_cleanup() calls. It detaches the
 * handle from a multi handle or a connection, stops timers, closes the TLS
 * sessions, saves alt-svc/HSTS/cookie state and finally zeroes and frees
 * the handle itself. SIGPIPE is ignored while this runs when it is called
 * from curl_easy_cleanup().
 *
 * @param[in,out] datap  address of the handle pointer. It is set to NULL
 *                       before any work is done.
 * @return CURLE_OK always, also when @p datap or *datap is NULL.
 * @warning The handle must not be used afterwards. If it is part of a multi
 *          handle it gets removed from it first.
 * @see Curl_open()
 */
CURLcode Curl_close(struct Curl_easy **datap)
{
  struct Curl_easy *data;

  if(!datap || !*datap)
    return CURLE_OK;

  data = *datap;
  *datap = NULL;

  if(!data->state.internal && data->multi) {
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there.
       This detaches the connection. */
    Curl_multi_remove_handle(data->multi, data);
  }
  else {
    /* Detach connection if any is left. This should not be normal, but can be
       the case for example with CONNECT_ONLY + recv/send (test 556) */
    Curl_detach_connection(data);
    if(!data->state.internal && data->multi_easy) {
      /* when curl_easy_perform() is used, it creates its own multi handle to
         use and this is the one */
      curl_multi_cleanup(data->multi_easy);
      data->multi_easy = NULL;
    }
  }
  DEBUGASSERT(!data->conn || data->state.internal);

  Curl_expire_clear_all(data); /* shut off any timers left */

  if(data->state.rangestringalloc)
    curlx_free(data->state.range);

  /* release any resolve information this transfer kept */
  Curl_resolv_destroy_all(data);

  data->set.verbose = FALSE; /* no more calls to DEBUGFUNCTION */
  data->magic = 0; /* force a clear AFTER the possibly enforced removal from
                    * the multi handle and async dns shutdown. The multi
                    * handle might check the magic and so might any
                    * DEBUGFUNCTION invoked for tracing */

  /* freed here in case DONE was not called */
  Curl_req_free(&data->req, data);

  /* Close down all open SSL info and sessions */
  Curl_ssl_close_all(data);
  Curl_peer_unlink(&data->state.origin);
  Curl_peer_unlink(&data->state.initial_origin);
#ifndef CURL_DISABLE_RTSP
  Curl_peer_unlink(&data->state.rtsp_session_origin);
#endif
  Curl_ssl_free_certinfo(data);

  Curl_bufref_free(&data->state.referer);

  up_free(data);
  curlx_dyn_free(&data->state.headerb);
  Curl_flush_cookies(data, TRUE);
#ifndef CURL_DISABLE_ALTSVC
  Curl_altsvc_save(data, data->asi, CURL_EASY_STR(data, STRING_ALTSVC));
  Curl_altsvc_cleanup(&data->asi);
#endif
#ifndef CURL_DISABLE_HSTS
  Curl_hsts_save(data, data->hsts, CURL_EASY_STR(data, STRING_HSTS));
  if(!data->share || !data->share->hsts)
    Curl_hsts_cleanup(&data->hsts);
  curl_slist_free_all(data->state.hstslist); /* clean up list */
#endif
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_DIGEST_AUTH)
  Curl_http_auth_cleanup_digest(data);
#endif
  curlx_safefree(data->state.most_recent_ftp_entrypath);
  curlx_safefree(data->info.contenttype);
  curlx_safefree(data->info.wouldredirect);
  curlx_safefree(data->info.effective_url);

  /* No longer a dirty share, if it exists */
  if(Curl_share_easy_unlink(data))
    DEBUGASSERT(0);

  Curl_hash_destroy(&data->meta_hash);
  Curl_creds_unlink(&data->state.creds);
#ifndef CURL_DISABLE_HTTP
  curlx_safefree(data->state.rangeline);
  curlx_safefree(data->state.http_host);
#endif
#ifndef CURL_DISABLE_COOKIES
  curlx_safefree(data->req.cookiehost);
#endif

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_FORM_API)
  Curl_mime_cleanpart(data->state.formp);
  curlx_safefree(data->state.formp);
#endif

  /* destruct wildcard structures if it is needed */
  Curl_wildcard_dtor(&data->wildcard);
  Curl_freeset(data);
  Curl_headers_cleanup(data);
  Curl_netrc_cleanup(&data->state.netrc);
#ifndef CURL_DISABLE_DIGEST_AUTH
  curlx_free(data->state.envproxy);
#endif
  curlx_memzero(data, sizeof(*data));
  curlx_free(data);
  return CURLE_OK;
}

/**
 * @brief Set the user-modifiable options to their defaults.
 *
 * Initializes data->set (UserDefined): stdio streams, write/read callbacks,
 * default timeouts, auth methods, TLS minimums, TCP keepalive, buffer sizes
 * and per-protocol defaults. Fields guarded by feature macros are only
 * touched when the feature is built in.
 *
 * @param[in,out] data  transfer handle, may be new or already in use.
 * @note Safe to call on a new or an existing Curl_easy, e.g. from
 *       curl_easy_reset().
 * @see Curl_freeset()
 */
void Curl_init_userdefined(struct Curl_easy *data)
{
  struct UserDefined *set = &data->set;

  set->out = stdout;  /* default output to stdout */
  set->in_set = stdin;  /* default input from stdin */
  set->err = stderr;  /* default stderr to stderr */

  Curl_u8_strset_init(&data->set.strings);

#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
  /* use fwrite as default function to store output */
  set->fwrite_func = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  set->fread_func_set = (curl_read_callback)fread;
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
  set->is_fread_set = 0;

  set->seek_client = ZERO_NULL;

  set->filesize = -1;        /* we do not know the size */
  set->postfieldsize = -1;   /* unknown size */
  set->maxredirs = 30;       /* sensible default */

  set->method = HTTPREQ_GET; /* Default HTTP request */
#ifndef CURL_DISABLE_RTSP
  set->rtspreq = RTSPREQ_OPTIONS; /* Default RTSP request */
#endif
#ifndef CURL_DISABLE_FTP
  set->ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
  set->ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */
  set->ftp_use_pret = FALSE;  /* mainly useful for drftpd servers */
  set->ftp_filemethod = FTPFILE_MULTICWD;
  set->ftp_skip_ip = TRUE;    /* skip PASV IP by default */
#endif
  set->dns_cache_timeout_ms = 60000; /* Timeout every 60 seconds by default */

  /* Timeout every 24 hours by default */
  set->ssl_ca_cache_timeout = 24 * 60 * 60;

  set->httpauth = CURLAUTH_BASIC;  /* defaults to basic */

  Curl_ssl_config_init(&data->set.ssl);
#ifndef CURL_DISABLE_PROXY
  Curl_ssl_config_init(&data->set.proxy_ssl);
  set->proxyport = 0;
  set->proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */
  set->proxyauth = CURLAUTH_BASIC; /* defaults to basic */
  /* SOCKS5 proxy auth defaults to username/password + GSS-API */
  set->socks5auth = CURLAUTH_BASIC | CURLAUTH_GSSAPI;
#endif

#ifndef CURL_DISABLE_DOH
  set->doh_verifyhost = TRUE;
  set->doh_verifypeer = TRUE;
#endif
#ifdef USE_SSH
  /* defaults to any auth type */
  set->ssh_auth_types = CURLSSH_AUTH_DEFAULT;
  set->new_directory_perms = 0755; /* Default permissions */
#endif

  set->new_file_perms = 0644;    /* Default permissions */
  set->allowed_protocols = (curl_prot_t)CURLPROTO_64ALL;
  set->redir_protocols = CURLPROTO_REDIR;

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  /*
   * disallow unprotected protection negotiation NEC reference implementation
   * seem not to follow rfc1961 section 4.3/4.4
   */
  set->socks5_gssapi_nec = FALSE;
#endif

  /* set default minimum TLS version */
#ifdef USE_SSL
  Curl_setopt_SSLVERSION(data, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
#ifndef CURL_DISABLE_PROXY
  Curl_setopt_SSLVERSION(data, CURLOPT_PROXY_SSLVERSION,
                         CURL_SSLVERSION_DEFAULT);
#endif
#endif
#ifndef CURL_DISABLE_FTP
  set->wildcard_enabled = FALSE;
  set->chunk_bgn = ZERO_NULL;
  set->chunk_end = ZERO_NULL;
  set->fnmatch = ZERO_NULL;
#endif
  set->tcp_keepalive = FALSE;
  set->tcp_keepintvl = 60;
  set->tcp_keepidle = 60;
  set->tcp_keepcnt = 9;
  set->tcp_fastopen = FALSE;
  set->tcp_nodelay = TRUE;
  set->ssl_enable_alpn = TRUE;
  set->expect_100_timeout = 1000L; /* Wait for a second by default. */
  set->sep_headers = TRUE; /* separated header lists by default */
  set->buffer_size = READBUFFER_SIZE;
  set->upload_buffer_size = UPLOADBUFFER_DEFAULT;
  set->upload_flags = CURLULFLAG_SEEN;
  set->happy_eyeballs_timeout = CURL_HET_DEFAULT;
  set->upkeep_interval_ms = CURL_UPKEEP_INTERVAL_DEFAULT;
  set->maxconnects = DEFAULT_CONNCACHE_SIZE; /* for easy handles */
  set->conn_max_idle_ms = 118 * 1000;
  set->conn_max_age_ms = 24 * 3600 * 1000;
  set->http09_allowed = FALSE;
  set->httpwant = CURL_HTTP_VERSION_NONE;
#if defined(USE_HTTP2) || defined(USE_HTTP3)
  set->weight = 0;
#endif
  set->quick_exit = 0L;
#ifndef CURL_DISABLE_WEBSOCKETS
  set->ws_raw_mode = FALSE;
  set->ws_no_auto_pong = FALSE;
#endif
}

/**
 * @brief Destructor callback for data->meta_hash entries.
 * @internal
 *
 * Elements must be added with their own destructor, so this default one
 * should never be called with a non-NULL pointer.
 *
 * @param[in] p  stored element (unused, asserted to be NULL).
 * @warning Only reached on programming errors.
 */
static void easy_meta_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(!p);
}

/**
 * @brief Allocate and initialize a new transfer handle.
 *
 * Callocs a struct Curl_easy, sets the magic number, invalid ids, buffers
 * (dynbuf, bufref), the request and info structs, and applies the default
 * options.
 *
 * @param[out] curl  receives the new handle on success, untouched on error.
 * @return CURLE_OK on success
 * @retval CURLE_OUT_OF_MEMORY the handle could not be allocated.
 * @post On success *curl is owned by the caller, free with Curl_close().
 * @see Curl_close(), Curl_init_userdefined()
 */
CURLcode Curl_open(struct Curl_easy **curl)
{
  struct Curl_easy *data;

  /* simple start-up: alloc the struct, init it with zeroes and return */
  data = curlx_calloc(1, sizeof(struct Curl_easy));
  if(!data) {
    /* this is a serious error */
    DEBUGF(curl_mfprintf(stderr, "Error: calloc of Curl_easy failed\n"));
    return CURLE_OUT_OF_MEMORY;
  }

  data->magic = CURLEASY_MAGIC_NUMBER;
  /* most recent connection is not yet defined */
  data->state.last_conn_id = -1;
  data->state.last_cpid = UINT32_MAX;
  /* and not assigned an id yet */
  data->id = -1;
  data->mid = UINT32_MAX;
  data->master_mid = UINT32_MAX;
  data->progress.hide = TRUE;

  Curl_hash_init(&data->meta_hash, 23, CURL_HASH_TYPE_BYTES,
                 easy_meta_freeentry);
  DEBUGASSERT(STRING_LAST <= UINT8_MAX);
  Curl_u8_strset_init(&data->set.strings);
  curlx_dyn_init(&data->state.headerb, CURL_MAX_HTTP_HEADER);
  Curl_bufref_init(&data->state.url);
  Curl_bufref_init(&data->state.referer);
  Curl_req_init(&data->req);
  Curl_initinfo(data);
#ifndef CURL_DISABLE_HTTP
  Curl_llist_init(&data->state.httphdrs, NULL);
#endif
  Curl_netrc_init(&data->state.netrc);
  Curl_init_userdefined(data);

  *curl = data;
  return CURLE_OK;
}

/**
 * @brief Free a connection and everything it owns.
 *
 * Calls the protocol disconnect handler (unless the shutdown handler already
 * did), discards all connection filters, unlinks peers and credentials,
 * frees option strings and the metadata hash, then the struct itself.
 *
 * @param[in] data  transfer used for callbacks and tracing.
 * @param[in] conn  connection to free, must not be NULL.
 * @warning @p conn is invalid after this call. It must already be detached
 *          from the connection pool and from all transfers.
 * @see allocate_conn()
 */
void Curl_conn_free(struct Curl_easy *data, struct connectdata *conn)
{
  int8_t i;

  DEBUGASSERT(conn);

  if(conn->scheme && conn->scheme->run->disconnect &&
     !conn->bits.shutdown_handler)
    conn->scheme->run->disconnect(data, conn, TRUE);

  for(i = 0; i < (int8_t)CURL_ARRAYSIZE(conn->cfilter); ++i) {
    Curl_conn_cf_discard_all(data, conn, i);
  }

#ifndef CURL_DISABLE_PROXY
  Curl_peer_unlink(&conn->http_proxy.peer);
  Curl_peer_unlink(&conn->socks_proxy.peer);
  Curl_creds_unlink(&conn->http_proxy.creds);
  Curl_creds_unlink(&conn->socks_proxy.creds);
#endif
  Curl_creds_unlink(&conn->creds);
  Curl_peer_unlink(&conn->creds_origin);
  curlx_safefree(conn->options);
  curlx_safefree(conn->interface_opts);
  Curl_ssl_conn_config_cleanup(conn);

  curlx_safefree(conn->destination);
  Curl_hash_destroy(&conn->meta_hash);
  Curl_peer_unlink(&conn->origin);
  Curl_peer_unlink(&conn->via_peer);
  Curl_peer_unlink(&conn->origin2);
  Curl_peer_unlink(&conn->via_peer2);

  curlx_free(conn); /* free all the connection oriented data */
}

/**
 * @brief Tell if a transfer could be run on a multiplexed connection.
 * @internal
 *
 * True for HTTP family schemes when the multi handle wants multiplexing,
 * HTTP/2 or newer is allowed, and the connection is not closing.
 *
 * @param[in] data  transfer with the HTTP negotiation state.
 * @param[in] conn  (template) connection to be used.
 * @return TRUE if multiplexing is possible, FALSE otherwise (always FALSE
 *         when HTTP is disabled).
 */
static bool xfer_may_multiplex(const struct Curl_easy *data,
                               const struct connectdata *conn)
{
#ifndef CURL_DISABLE_HTTP
  /* If an HTTP protocol and multiplexing is enabled */
  if((conn->scheme->protocol & PROTO_FAMILY_HTTP) &&
     (!conn->bits.protoconnstart || !conn->bits.close)) {

    if(Curl_multiplex_wanted(data->multi) &&
       (data->state.http_neg.allowed & (CURL_HTTP_V2x | CURL_HTTP_V3x)))
      /* allows HTTP/2 or newer */
      return TRUE;
  }
#else
  (void)data;
  (void)conn;
#endif
  return FALSE;
}

#ifndef CURL_DISABLE_PROXY
/**
 * @brief Compare two proxy descriptions for connection reuse.
 * @internal
 *
 * @param[in] data    proxy info of an existing connection.
 * @param[in] needle  proxy info the transfer wants.
 * @return TRUE if proxy type, destination and credentials are all the same.
 */
static bool proxy_info_matches(const struct proxy_info *data,
                               const struct proxy_info *needle)
{
  if((data->proxytype == needle->proxytype) &&
     Curl_peer_same_destination(data->peer, needle->peer) &&
     Curl_creds_same(data->creds, needle->creds)) {
    return TRUE;
  }
  return FALSE;
}
#endif

#ifdef USE_SSH
/**
 * @brief Compare the SSH key settings of two connections.
 * @internal
 *
 * @param[in] one  first connection.
 * @param[in] two  second connection.
 * @return TRUE if both have SSH state and equal private and public keys.
 */
static bool ssh_config_matches(struct connectdata *one,
                               struct connectdata *two)
{
  struct ssh_conn *sshc1, *sshc2;

  sshc1 = Curl_conn_meta_get(one, CURL_META_SSH_CONN);
  sshc2 = Curl_conn_meta_get(two, CURL_META_SSH_CONN);
  return sshc1 && sshc2 && Curl_safecmp(sshc1->priv_key, sshc2->priv_key) &&
         Curl_safecmp(sshc1->pub_key, sshc2->pub_key);
}
#endif

/**
 * @brief State of one search for a reusable connection in the pool.
 * @internal
 *
 * Filled by url_match_init(), consulted by the url_match_* predicates while
 * the pool is scanned and finally evaluated by url_match_result().
 * @ingroup url_conn_reuse
 */
struct url_conn_match {
  /** The matching connection once found, else NULL. */
  struct connectdata *found;
  /** Transfer looking for a connection. */
  struct Curl_easy *data;
  /** Template connection describing the wanted one. */
  struct connectdata *needle;
  /** Timestamp used for age and health checks. */
  struct curltime now;
  /** Shallow TLS config of the needle for matching. */
  struct ssl_filter_config ssl_config;
#ifndef CURL_DISABLE_PROXY
  /** Shallow TLS config of the HTTPS proxy. */
  struct ssl_filter_config proxy_ssl_config;
#endif
  /** Transfer may share a multiplexed connection. */
  BIT(may_multiplex);
  /** Transfer wants HTTP Negotiate authentication. */
  BIT(want_nego_http);
  /** Transfer wants Negotiate to the HTTP proxy. */
  BIT(want_proxy_nego_http);
  BIT(may_tls); /* May upgrade clear-text connection to TLS, can only reuse
                 * connections that have matching TLS configuration.
                 * Always TRUE if `req_tls` is TRUE. */
  BIT(require_tls); /* Requires TLS use from a clear-text start, can only
                 * reuse connections that have TLS. */
  /** Wait for a connection to finish multiplex negotiation. */
  BIT(wait_pipe);
  /** Saw a candidate that is not fully connected yet. */
  BIT(seen_pending_conn);
  /** Saw a busy connection that cannot multiplex. */
  BIT(seen_single_use_conn);
  /** Saw a busy connection that can multiplex. */
  BIT(seen_multiplex_conn);
};

/**
 * @brief Check general connect settings of a candidate connection.
 * @internal
 *
 * Rejects connect-only, closing and no-reuse connections, and requires
 * matching IP version, local port/range and interface bind options. A
 * connection using "connect to" must not be mixed with one that does not.
 *
 * @param[in] conn  candidate connection from the pool.
 * @param[in] m     match state holding the needle and transfer.
 * @return TRUE if the candidate passes, FALSE to skip it.
 * @ingroup url_conn_reuse
 */
static bool url_match_connect_config(struct connectdata *conn,
                                     struct url_conn_match *m)
{
  /* connect-only or to-be-closed connections will not be reused */
  if(conn->bits.connect_only || conn->bits.close || conn->bits.no_reuse)
    return FALSE;

  /* ip_version must match */
  if(m->data->set.ipver != CURL_IPRESOLVE_WHATEVER &&
     m->data->set.ipver != conn->ip_version)
    return FALSE;

  /* When needle has specific local bind settings, those have to match.
   * If it does not, any other connection might do when it comes to ports. */
  if(m->needle->localport &&
     ((conn->localport != m->needle->localport) ||
      (conn->localportrange != m->needle->localportrange)))
    return FALSE;
  /* For interface related bind options, we require a full match
   * as connection might go totally different ways (VPNs, for example). */
  if((m->needle->interface_opts != conn->interface_opts) &&
     (!m->needle->interface_opts || !conn->interface_opts ||
      strcmp(conn->interface_opts, m->needle->interface_opts)))
    return FALSE;

  if((m->needle->interface_opts || m->needle->localport) &&
    /* If we are bound to a specific local end (IP+port), we must not reuse a
       random other one, although if we did not ask for a particular one we
       can reuse one that was bound. */
    ((conn->localport != m->needle->localport) ||
     (conn->localportrange != m->needle->localportrange) ||
     (m->needle->interface_opts &&
      (!conn->interface_opts ||
       strcmp(conn->interface_opts, m->needle->interface_opts)))))
    return FALSE;

  if(!m->needle->via_peer != !conn->via_peer)
    /* do not mix connections that use the "connect to host" feature and
     * connections that do not use this feature */
    return FALSE;

  return TRUE;
}

/**
 * @brief Check that a candidate is connected and not upgrading.
 * @internal
 *
 * @param[in]     conn  candidate connection.
 * @param[in,out] m     match state, seen_pending_conn is set when a
 *                      multiplex-capable transfer meets an unfinished conn.
 * @return TRUE if fully connected, FALSE otherwise.
 * @ingroup url_conn_reuse
 */
static bool url_match_fully_connected(struct connectdata *conn,
                                      struct url_conn_match *m)
{
  if(!Curl_conn_is_connected(conn, FIRSTSOCKET) ||
     conn->bits.upgrade_in_progress) {
    /* Not yet connected, or a protocol upgrade is in progress. The later
     * happens for HTTP/2 Upgrade: requests that need a response. */
    if(m->may_multiplex) {
      m->seen_pending_conn = TRUE;
      /* Do not pick a connection that has not connected yet */
      infof(m->data, "Connection #%" FMT_OFF_T
            " is not open enough, cannot reuse", conn->connection_id);
    }
    /* Do not pick a connection that has not connected yet */
    return FALSE;
  }
  return TRUE;
}

/**
 * @brief Check that a busy connection belongs to the same multi handle.
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return FALSE if @p conn is in use by another multi handle, else TRUE.
 * @ingroup url_conn_reuse
 */
static bool url_match_multi(struct connectdata *conn,
                            struct url_conn_match *m)
{
  if(CONN_INUSE(conn)) {
    DEBUGASSERT(conn->attached_multi);
    if(conn->attached_multi != m->data->multi)
      return FALSE;
  }
  return TRUE;
}

/**
 * @brief Check that a busy connection can take one more transfer.
 * @internal
 *
 * Idle connections always pass. A busy one passes only if it multiplexes
 * and the transfer may multiplex on it within the same multi handle. Records
 * what was seen in @p m for url_match_result().
 *
 * @param[in]     conn  candidate connection.
 * @param[in,out] m     match state, seen_* flags may be set.
 * @return TRUE if usable, FALSE if the candidate must be skipped.
 * @ingroup url_conn_reuse
 */
static bool url_match_multiplex_needs(struct connectdata *conn,
                                      struct url_conn_match *m)
{
  if(CONN_INUSE(conn)) {
    if(!conn->bits.multiplex) {
      /* conn busy and conn cannot take more transfers */
      m->seen_single_use_conn = TRUE;
      return FALSE;
    }
    m->seen_multiplex_conn = TRUE;
    if(!m->may_multiplex || !url_match_multi(conn, m))
      /* conn busy and transfer cannot be multiplexed */
      return FALSE;
  }
  return TRUE;
}

/**
 * @brief Enforce stream concurrency limits on a multiplexed candidate.
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return FALSE if the connection reached the multi handle's or the
 *         server's MAX_CONCURRENT_STREAMS, otherwise TRUE.
 * @ingroup url_conn_reuse
 */
static bool url_match_multiplex_limits(struct connectdata *conn,
                                       struct url_conn_match *m)
{
  if(CONN_INUSE(conn) && m->may_multiplex) {
    DEBUGASSERT(conn->bits.multiplex);
    /* If multiplexed, make sure we do not go over concurrency limit */
    if(conn->attached_xfers >=
            Curl_multi_max_concurrent_streams(m->data->multi)) {
      infof(m->data, "connection #%" FMT_OFF_T " reached "
            "MAX_CONCURRENT_STREAMS(%u), skip",
            conn->connection_id, conn->attached_xfers);
      return FALSE;
    }
    if(conn->attached_xfers >=
       Curl_conn_get_max_concurrent(m->data, conn, FIRSTSOCKET)) {
      infof(m->data, "connection #%" FMT_OFF_T "reached "
            "MAX_CONCURRENT_STREAMS(%u), skip",
            conn->connection_id, conn->attached_xfers);
      return FALSE;
    }
    /* When not multiplexed, we have a match here! */
    infof(m->data, "Multiplexed connection found");
  }
  return TRUE;
}

/**
 * @brief Check that TLS usage of a candidate fits the wanted scheme.
 * @internal
 *
 * A TLS scheme needs a TLS connection. A clear-text scheme may reuse a TLS
 * connection only if its protocol allows it (auto-upgrade, same family) and
 * the SSL config matches. A required STARTTLS cannot use clear-text.
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE on match, FALSE otherwise.
 * @ingroup url_conn_reuse
 */
static bool url_match_ssl_use(struct connectdata *conn,
                              struct url_conn_match *m)
{
  if(m->needle->scheme->flags & PROTOPT_SSL) {
    /* We are looking for SSL, if `conn` does not do it, not a match. */
    if(!Curl_conn_is_ssl(conn, FIRSTSOCKET))
      return FALSE;
  }
  else if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    /* If the protocol does not allow reuse of SSL connections OR
       is of another protocol family, not a match. */
    if(!(m->needle->scheme->flags & PROTOPT_SSL_REUSE) ||
       (get_protocol_family(conn->scheme) != m->needle->scheme->protocol))
      return FALSE;
    /* We may reuse this as an auto-TLS upgrade, but only if the SSL
     * config parameters match. */
    if(!Curl_ssl_conn_config_match(m->data, &m->ssl_config, conn, FALSE))
      return FALSE;
  }
  else if(m->require_tls)
    /* a clear-text STARTTLS protocol with required TLS */
    return FALSE;
  return TRUE;
}

#ifndef CURL_DISABLE_PROXY
/**
 * @brief Check that proxy settings of a candidate equal the needle's.
 * @internal
 *
 * Compares origin-is-proxy, SOCKS and HTTP proxy descriptions, SOCKS5
 * authentication state and, for HTTPS proxies, the proxy TLS config.
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE if the proxy setups are compatible, FALSE otherwise.
 * @note With proxy support disabled this is a macro that always yields TRUE.
 * @ingroup url_conn_reuse
 */
static bool url_match_proxy_use(struct connectdata *conn,
                                struct url_conn_match *m)
{
  if(m->needle->bits.origin_is_proxy != conn->bits.origin_is_proxy)
    return FALSE;

  if(!proxy_info_matches(&m->needle->socks_proxy, &conn->socks_proxy))
    return FALSE;

  if(!proxy_info_matches(&m->needle->http_proxy, &conn->http_proxy))
    return FALSE;

  if(m->data->set.socks5_auth_only && !conn->bits.socks5_authenticated &&
     ((conn->socks_proxy.proxytype == CURLPROXY_SOCKS5) ||
      (conn->socks_proxy.proxytype == CURLPROXY_SOCKS5_HOSTNAME))) {
    DEBUGF(infof(m->data,
                 "Connection #%" FMT_OFF_T
                 " was not SOCKS5 authenticated, cannot reuse",
                 conn->connection_id));
    return FALSE;
  }

  if(CURL_PROXY_IS_HTTPS(m->needle->http_proxy.proxytype)) {
    /* https proxies come in different types, http/1.1, h2, ... */
    /* match SSL config to proxy */
    if(!Curl_ssl_conn_config_match(m->data, &m->proxy_ssl_config,
                                   conn, TRUE)) {
      DEBUGF(infof(m->data,
                   "Connection #%" FMT_OFF_T
                   " has different SSL proxy parameters, cannot reuse",
                   conn->connection_id));
      return FALSE;
    }
    /* the SSL config to the server, which may apply here is checked
     * further below */
  }
  return TRUE;
}
#else
#define url_match_proxy_use(c, m) ((void)(c), (void)(m), TRUE)
#endif

#ifndef CURL_DISABLE_HTTP
/**
 * @brief Handle candidates whose HTTP version is not yet known.
 * @internal
 *
 * If the transfer may multiplex but the connection has not seen an HTTP
 * version yet, either ask to wait (CURLOPT_PIPEWAIT) or skip it.
 *
 * @param[in]     conn        candidate connection.
 * @param[in,out] m           match state, m->found is cleared when waiting.
 * @param[out]    pwait_pipe  set TRUE when the transfer should wait.
 * @return TRUE to continue (or to stop the search when waiting), FALSE to
 *         skip this candidate.
 * @ingroup url_conn_reuse
 */
static bool url_match_http_multiplex(struct connectdata *conn,
                                     struct url_conn_match *m,
                                     bool *pwait_pipe)
{
  if(m->may_multiplex &&
     (m->data->state.http_neg.allowed & (CURL_HTTP_V2x | CURL_HTTP_V3x)) &&
     (m->needle->scheme->protocol & CURLPROTO_HTTP) &&
     !conn->httpversion_seen) {
    if(m->data->set.pipewait) {
      infof(m->data, "Server upgrade does not support multiplex yet, wait");
      m->found = NULL;
      *pwait_pipe = TRUE;
      return TRUE; /* stop searching, we want to wait */
    }
    infof(m->data, "Server upgrade cannot be used");
    return FALSE;
  }
  return TRUE;
}

/**
 * @brief Check that the HTTP version of a candidate is allowed.
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return FALSE if the connection speaks h1, h2 or h3 and the transfer's
 *         allowed versions exclude it, otherwise TRUE.
 * @ingroup url_conn_reuse
 */
static bool url_match_http_version(struct connectdata *conn,
                                   struct url_conn_match *m)
{
  /* If looking for HTTP and the HTTP versions allowed do not include
   * the HTTP version of conn, continue looking. */
  if((m->needle->scheme->protocol & PROTO_FAMILY_HTTP)) {
    switch(Curl_conn_http_version(m->data, conn)) {
    case 30:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V3x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h3", conn->connection_id));
        return FALSE;
      }
      break;
    case 20:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V2x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h2", conn->connection_id));
        return FALSE;
      }
      break;
    default:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V1x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h1", conn->connection_id));
        return FALSE;
      }
      break;
    }
  }
  return TRUE;
}
#else
#define url_match_http_multiplex(c, m, w) ((void)(c), (void)(m), TRUE)
#define url_match_http_version(c, m)      ((void)(c), (void)(m), TRUE)
#endif

/**
 * @brief Check protocol specific settings (HTTP version, SSH, FTP).
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE if the protocol specific configuration matches.
 * @ingroup url_conn_reuse
 */
static bool url_match_proto_config(struct connectdata *conn,
                                   struct url_conn_match *m)
{
  if(!url_match_http_version(conn, m))
    return FALSE;

#ifdef USE_SSH
  if(get_protocol_family(m->needle->scheme) & PROTO_FAMILY_SSH) {
    if(!ssh_config_matches(m->needle, conn))
      return FALSE;
  }
#endif
#ifndef CURL_DISABLE_FTP
  else if(get_protocol_family(m->needle->scheme) & PROTO_FAMILY_FTP) {
    if(!Curl_ftp_conns_match(m->needle, conn))
      return FALSE;
  }
#endif
  return TRUE;
}

/**
 * @brief Check that credentials of a candidate fit the transfer.
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE if the needle credentials (or transfer credentials when the
 *         needle has none) equal the connection's, and GSS delegation
 *         settings agree. FALSE otherwise.
 * @ingroup url_conn_reuse
 */
static bool url_match_auth(struct connectdata *conn,
                           struct url_conn_match *m)
{
  if(!Curl_creds_same(m->needle->creds, conn->creds)) {
    if(m->needle->creds)
      return FALSE;
    if(!Curl_creds_same(m->data->state.creds, conn->creds))
      return FALSE;
  }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  /* GSS delegation differences do not actually affect every connection and
     auth method, but this check takes precaution before efficiency */
  if(m->needle->gssapi_delegation != conn->gssapi_delegation)
    return FALSE;
#endif

  return TRUE;
}

/**
 * @brief Check that origin and "connect to" peer of a candidate match.
 * @internal
 *
 * Different via-peers never match. A scheme mismatch is allowed within the
 * same protocol family when the connection uses TLS (IMAP+STARTTLS for
 * IMAPS, IMAPS for IMAP). Then host name and port are compared.
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE if the destinations are the same.
 * @ingroup url_conn_reuse
 */
static bool url_match_destination(struct connectdata *conn,
                                  struct url_conn_match *m)
{
  /* Different connect-to peers never match */
  if(!Curl_peer_same_destination(m->needle->via_peer, conn->via_peer))
    return FALSE;

  if(m->needle->origin->scheme != conn->origin->scheme &&
    /* `needle` and `conn` not having the same scheme.
     * This is allowed for the same family *if* conn is using TLS.
     * - IMAP+STARTTLS works for IMAPS.
     * - IMAPS works for IMAP. */
     get_protocol_family(conn->origin->scheme) !=
     m->needle->scheme->protocol)
    return FALSE;

  /* Scheme mismatch is acceptable, compare hostname/port */
  return Curl_peer_same_destination(m->needle->origin, conn->origin);
}

/**
 * @brief Check that TLS options of a candidate equal the needle's.
 * @internal
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return FALSE if TLS is wanted or possible and the SSL parameters differ.
 * @ingroup url_conn_reuse
 */
static bool url_match_ssl_config(struct connectdata *conn,
                                 struct url_conn_match *m)
{
  /* If talking/upgrading to TLS, conn needs to use the same SSL options. */
  if(((m->needle->scheme->flags & PROTOPT_SSL) || m->may_tls) &&
     !Curl_ssl_conn_config_match(m->data, &m->ssl_config, conn, FALSE)) {
    DEBUGF(infof(m->data, "Connection #%" FMT_OFF_T
                 " has different SSL parameters, cannot reuse",
                 conn->connection_id));
    return FALSE;
  }
  return TRUE;
}

#ifdef USE_SPNEGO
/**
 * @brief Check Negotiate (SPNEGO) state compatibility.
 * @internal
 *
 * A connection already in a Negotiate exchange is only reusable by a
 * transfer with the same credentials and origin; the same rule applies to
 * HTTP proxy Negotiate. Otherwise credentials bound to another origin block
 * reuse.
 *
 * @param[in] conn  candidate connection.
 * @param[in] m     match state.
 * @return TRUE if reuse is acceptable.
 * @note Compiled to a TRUE macro without SPNEGO.
 * @ingroup url_conn_reuse
 */
static bool url_match_auth_nego(struct connectdata *conn,
                                struct url_conn_match *m)
{
  if(conn->http_negotiate_state != CURL_NEGO_AUTH_NONE) {
    /* Connection is using Negotiate. We cannot reuse if transfer
     * has different Auth input parameters. */
    if(!m->want_nego_http ||
       !Curl_creds_same(conn->creds, m->data->state.creds) ||
       !Curl_peer_equal(conn->creds_origin, m->data->state.origin))
      return FALSE;
  }
  else if(m->want_nego_http) {
    /* Transfer wants Negotiate, connection is not using it.
     * Do not reuse when connection credentials state is bound to an origin
     * and it or creds differ. */
    if(conn->creds_origin &&
       (!Curl_creds_same(conn->creds, m->data->state.creds) ||
        !Curl_peer_equal(conn->creds_origin, m->data->state.origin)))
      return FALSE;
  }

#ifndef CURL_DISABLE_PROXY
  /* Same for Proxy Negotiate authentication */
  if(conn->proxy_negotiate_state != CURL_NEGO_AUTH_NONE) {
    if(!m->want_proxy_nego_http ||
       !Curl_creds_same(m->needle->http_proxy.creds, conn->http_proxy.creds))
      return FALSE;
  }
  else if(m->want_proxy_nego_http) {
    if(conn->http_proxy.creds &&
       !Curl_creds_same(m->needle->http_proxy.creds, conn->http_proxy.creds))
      return FALSE;
  }
#endif
  return TRUE;
}
#else
#define url_match_auth_nego(c, m) ((void)(c), (void)(m), TRUE)
#endif

/**
 * @brief Connection pool callback: does @p conn fit the wanted connection.
 * @internal
 *
 * Runs all url_match_* predicates in sequence, then applies connection age
 * and health checks.
 *
 * @param[in]     conn      pooled connection to evaluate.
 * @param[in,out] userdata  struct url_conn_match for this search.
 * @return CPOOL_MATCH_CONT to continue with the next candidate
 * @retval CPOOL_MATCH_FOUND  usable (m->found set) or a wait is requested
 * @retval CPOOL_MATCH_TOO_OLD  older than the max connection age
 * @retval CPOOL_MATCH_CLOSE  idle but looks dead, pool should close it
 * @ingroup url_conn_reuse
 */
static cpool_match_result url_match_conn(struct connectdata *conn,
                                         void *userdata)
{
  struct url_conn_match *m = userdata;
  bool wait_pipe = FALSE;

  /* general connect config setting match? */
  if(!url_match_connect_config(conn, m))
    return CPOOL_MATCH_CONT;

  /* match for destination and protocol? */
  if(!url_match_destination(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_fully_connected(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_multiplex_needs(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_ssl_use(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_proxy_use(conn, m))
    return CPOOL_MATCH_CONT;
  if(!url_match_ssl_config(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_http_multiplex(conn, m, &wait_pipe))
    return CPOOL_MATCH_CONT;

  if(!url_match_auth(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_proto_config(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_auth_nego(conn, m))
    return CPOOL_MATCH_CONT;

  if(!url_match_multiplex_limits(conn, m))
    return CPOOL_MATCH_CONT;

  /* The connection matches all conditions, but do we want to use it? */
  if(wait_pipe) {
    /* The connection fits, but it's multiplex state has not been determined
     * yet. Put the transfer into PENDING and wait for conn state change. */
    DEBUGASSERT(!m->found);
    m->wait_pipe = TRUE;
    return CPOOL_MATCH_FOUND;
  }

  if(m->data->set.conn_max_age_ms > 0) {
    timediff_t age_ms = Curl_cpool_conn_age_ms(m->data, conn, &m->now);
    if(age_ms > m->data->set.conn_max_age_ms) {
      /* Transfer is looking for a younger connection. */
      return CPOOL_MATCH_TOO_OLD;
    }
  }

  /* If we are going to pick an idle connection, do an extra
   * health check before we reuse it. */
  if(!CONN_INUSE(conn) &&
     !Curl_cpool_conn_seems_healthy(conn, m->data, &m->now)) {
    infof(m->data, "Connection %" FMT_OFF_T " seems to be dead, terminating",
          conn->connection_id);
    return CPOOL_MATCH_CLOSE;
  }

  /* conn matches our needs. */
  m->found = conn;
  return CPOOL_MATCH_FOUND;
}

/**
 * @brief Connection pool callback run after scanning, still under lock.
 * @internal
 *
 * Attaches the found connection immediately so it cannot be reaped. When
 * nothing was found it decides whether to wait for multiplexing: no wait if
 * only single-use connections exist, wait if CURLOPT_PIPEWAIT is set and a
 * pending candidate was seen.
 *
 * @param[in,out] userdata  struct url_conn_match of the search.
 * @return TRUE if a connection was attached, FALSE otherwise.
 * @ingroup url_conn_reuse
 */
static bool url_match_result(void *userdata)
{
  struct url_conn_match *match = userdata;
  if(match->found) {
    /* Attach it now while still under lock, so the connection does
     * no longer appear idle and can be reaped. */
    Curl_attach_connection(match->data, match->found, TRUE);
    return TRUE;
  }
  else if(match->seen_single_use_conn && !match->seen_multiplex_conn) {
    /* We have seen a single-use, existing connection to the destination and
     * no multiplexed one. It seems safe to assume that the server does
     * not support multiplexing. */
    match->wait_pipe = FALSE;
  }
  else if(match->seen_pending_conn && match->data->set.pipewait) {
    infof(match->data,
          "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set");
    match->wait_pipe = TRUE;
  }
  return FALSE;
}

/**
 * @brief Find and attach an existing connection that matches the needle.
 * @internal
 *
 * Given a transfer and a prototype connection (needle), searches the pool
 * for a matching connection and attaches it to the transfer.
 *
 * @param[in]     data    transfer to attach to.
 * @param[in]     needle  prototype of the wanted connection.
 * @param[in,out] m       match state, m->wait_pipe is TRUE if nothing matched
 *                        but a suitable connection might appear soon (common
 *                        cause: multiplexing not yet determined, e.g. ALPN).
 * @param[in]     pnow    current time.
 * @return TRUE if an existing connection was attached.
 */
static bool url_attach_existing(struct Curl_easy *data,
                                struct connectdata *needle,
                                struct url_conn_match *m,
                                const struct curltime *pnow)
{
  /* Find a connection in the pool that matches what "data + needle"
   * requires. If a suitable candidate is found, it is attached to "data". */
  return Curl_cpool_find(data, needle->destination, TRUE, pnow,
                         url_match_conn, url_match_result, m);
}

/**
 * @brief Allocate and initialize a new connectdata object.
 * @internal
 *
 * Sets sockets to invalid, copies bind parameters, IP version, FTP flags,
 * close-socket callbacks and GSS delegation from the transfer.
 *
 * @param[in] data  transfer providing the settings.
 * @return the new connection, or NULL on out-of-memory.
 * @post Caller owns the result, free with Curl_conn_free().
 */
static struct connectdata *allocate_conn(struct Curl_easy *data)
{
  struct connectdata *conn = curlx_calloc(1, sizeof(struct connectdata));
  if(!conn)
    return NULL;

  /* and we setup a few fields in case we end up actually using this struct */
  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     /* no file descriptor */
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->recv_idx = 0; /* default for receiving transfer data */
  conn->send_idx = 0; /* default for sending transfer data */
  conn->connection_id = -1;    /* no ID */
  conn->cpid = UINT32_MAX;  /* not in connection pool yet */
  conn->attached_xfers = 0;
  conn->connect_start_ms = -1;
  conn->shutdown.start_ms[FIRSTSOCKET] =
    conn->shutdown.start_ms[SECONDARYSOCKET] = -1;

#ifndef CURL_DISABLE_FTP
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;
#endif
  conn->ip_version = data->set.ipver;
  conn->bits.connect_only = (bool)data->set.connect_only;
  conn->transport_wanted = TRNSPRT_TCP; /* most of them are TCP streams */

  /* Store the local bind parameters that will be used for this connection */
  if(CURL_EASY_STR(data, STRING_INTERFACE_OPT)) {
    conn->interface_opts =
      curlx_strdup(CURL_EASY_STR(data, STRING_INTERFACE_OPT));
    if(!conn->interface_opts)
      goto error;
  }
#ifndef CURL_DISABLE_BINDLOCAL
  conn->localportrange = data->set.localportrange;
  conn->localport = data->set.localport;
#endif

  /* the close socket stuff needs to be copied to the connection struct as
     it may live on without (this specific) Curl_easy */
  conn->fclosesocket = data->set.fclosesocket;
  conn->closesocket_client = data->set.closesocket_client;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  conn->gssapi_delegation = data->set.gssapi_delegation;
#endif
  return conn;
error:

  curlx_free(conn->interface_opts);
  curlx_free(conn);
  return NULL;
}

/**
 * @brief Set the connection scheme if the transfer may use it.
 * @internal
 *
 * The scheme must have a run handler, be in the allowed protocols and, for
 * a redirect, in the allowed redirect protocols.
 *
 * @param[in]     data  transfer with the allowed protocol settings.
 * @param[in,out] conn  connection with origin set, gets conn->scheme.
 * @return CURLE_OK on success
 * @retval CURLE_UNSUPPORTED_PROTOCOL not allowed, disabled or no-transfer
 *         scheme (an error message is added).
 */
static CURLcode url_set_conn_scheme(struct Curl_easy *data,
                                    struct connectdata *conn)
{
  /* URL scheme is usable for connection when it is
   * - allowed
   * - not from a redirect or an allowed redirect protocol */
  const struct Curl_scheme *scheme = conn->origin->scheme;
  if(scheme->run &&
     (data->set.allowed_protocols & scheme->protocol) &&
     (!data->state.this_is_a_follow ||
       (data->set.redir_protocols & scheme->protocol))) {
    conn->scheme = scheme;
    return CURLE_OK;
  }
  if(scheme->flags & PROTOPT_NO_TRANSFER)
    failf(data, "Protocol \"%s\" is not for transfers", scheme->name);
  else
    failf(data, "Protocol \"%s\" is disabled%s", scheme->name,
          data->state.this_is_a_follow ? " (in redirect)" : "");
  return CURLE_UNSUPPORTED_PROTOCOL;
}

/**
 * @brief Convert a URL API error code to a CURLcode.
 *
 * @param[in] uc  result of a curl_url_set()/curl_url_get() call.
 * @return CURLE_UNSUPPORTED_PROTOCOL for CURLUE_UNSUPPORTED_SCHEME
 * @retval CURLE_OUT_OF_MEMORY for CURLUE_OUT_OF_MEMORY
 * @retval CURLE_LOGIN_DENIED for CURLUE_USER_NOT_ALLOWED
 * @retval CURLE_URL_MALFORMAT for every other code
 */
CURLcode Curl_uc_to_curlcode(CURLUcode uc)
{
  switch(uc) {
  default:
    return CURLE_URL_MALFORMAT;
  case CURLUE_UNSUPPORTED_SCHEME:
    return CURLE_UNSUPPORTED_PROTOCOL;
  case CURLUE_OUT_OF_MEMORY:
    return CURLE_OUT_OF_MEMORY;
  case CURLUE_USER_NOT_ALLOWED:
    return CURLE_LOGIN_DENIED;
  }
}

#ifndef CURL_DISABLE_HSTS
/**
 * @brief Upgrade an http:// transfer to https:// when HSTS applies.
 * @internal
 *
 * Rewrites the scheme in the CURLU handle, replaces the stored URL and
 * re-creates the origin peer.
 *
 * @param[in,out] data           transfer, state.url and state.origin change.
 * @param[in,out] uh             parsed URL, scheme set to https on upgrade.
 * @param[in]     port_override  port forced by CURLOPT_PORT or 0.
 * @param[in]     scope_id       IPv6 scope id or 0.
 * @return CURLE_OK if no upgrade was needed or it succeeded, otherwise the
 *         converted URL API error or the error from Curl_peer_from_url().
 * @note A macro returning CURLE_OK when HSTS is disabled.
 */
static CURLcode hsts_upgrade(struct Curl_easy *data,
                             CURLU *uh,
                             uint16_t port_override,
                             uint32_t scope_id)
{
  /* HSTS upgrade */
  if(data->hsts && (data->state.origin->scheme == &Curl_scheme_http) &&
     Curl_hsts_applies(data->hsts, data->state.origin)) {
    char *url;
    CURLUcode uc;
    CURLcode result;

    uc = curl_url_set(uh, CURLUPART_SCHEME, "https", 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    Curl_bufref_free(&data->state.url);
    /* after update, get the updated version */
    uc = curl_url_get(uh, CURLUPART_URL, &url, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    Curl_bufref_set(&data->state.url, url, 0, curl_free);

    result = Curl_peer_from_url(uh, data, port_override, scope_id,
                                &data->state.origin);
    if(result)
      return result;
    infof(data, "Switched from HTTP to HTTPS due to HSTS => %s", url);
  }
  return CURLE_OK;
}
#else
#define hsts_upgrade(x, y, z, a) CURLE_OK
#endif

/**
 * @brief Detect control characters in a string.
 * @internal
 *
 * @param[in] input  string to scan, may be NULL.
 * @return TRUE if any byte is below 0x20, FALSE otherwise (and for NULL).
 */
static bool str_has_ctrl(const char *input)
{
  if(input) {
    const unsigned char *str = (const unsigned char *)input;
    while(*str) {
      if(*str < 0x20)
        return TRUE;
      str++;
    }
  }
  return FALSE;
}

#ifndef CURL_DISABLE_NETRC
/**
 * @brief Complete or override transfer credentials from a .netrc file.
 * @internal
 *
 * Override the login details from the URL with that in the CURLOPT_USERPWD
 * option or a .netrc file, if applicable. Credentials set with CURLOPT_*
 * are never overridden; URL credentials are completed (or replaced when
 * netrc is required). Updated user and password are written back to the URL.
 *
 * @param[in]     data    transfer, uses state.origin and netrc settings.
 * @param[in,out] pcreds  credentials to merge with, may be replaced.
 * @return CURLE_OK on success (also when no netrc entry is found and netrc
 *         is optional)
 * @retval CURLE_OUT_OF_MEMORY allocation failure.
 * @retval CURLE_READ_ERROR netrc parse error or control codes in netrc
 *         credentials for a protocol that forbids them.
 * @note Only compiled without CURL_DISABLE_NETRC.
 */
static CURLcode url_set_data_creds_netrc(struct Curl_easy *data,
                                         struct Curl_creds **pcreds)
{
  struct Curl_creds *ncreds_out = NULL;
  CURLcode result = CURLE_OK;

  if(data->set.use_netrc) { /* not CURL_NETRC_IGNORED */
    struct Curl_creds *ncreds_in = NULL;
    bool scan_netrc = TRUE;
    NETRCcode ret;
    CURLUcode uc;

    if(*pcreds) {
      switch((*pcreds)->source) {
      case CREDS_OPTION:
        /* we never override credentials set via CURLOPT_*, leave. */
        scan_netrc = FALSE;
        break;
      case CREDS_URL: /* only apply when netrc is not required */
        if(data->set.use_netrc == CURL_NETRC_REQUIRED) {
          /* We ignore password from URL */
          ncreds_in = *pcreds;
        }
        else if(!Curl_creds_has_user(*pcreds) ||
                !Curl_creds_has_passwd(*pcreds)) {
          /* We use netrc to complete what is missing */
          ncreds_in = *pcreds;
        }
        else
          scan_netrc = FALSE;
        break;
      default: /* ignore credentials from other sources */
        break;
      }
    }

    if(!scan_netrc)
      goto out;

    ret = Curl_netrc_scan(data, &data->state.netrc,
                          data->state.origin->hostname,
                          Curl_creds_user(ncreds_in),
                          CURL_EASY_STR(data, STRING_NETRC_FILE),
                          &ncreds_out);
    DEBUGASSERT(!ret || !ncreds_out);
    if(ret == NETRC_OUT_OF_MEMORY) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    else if(ret && ((ret == NETRC_NO_MATCH) ||
                    (data->set.use_netrc == CURL_NETRC_OPTIONAL))) {
      infof(data, "Could not find host %s in the %s file; using defaults",
            data->state.origin->hostname,
            (CURL_EASY_STR(data, STRING_NETRC_FILE) ?
             CURL_EASY_STR(data, STRING_NETRC_FILE) : ".netrc"));
    }
    else if(ret) {
      const char *m = Curl_netrc_strerror(ret);
      failf(data, ".netrc error: %s", m);
      result = CURLE_READ_ERROR;
      goto out;
    }
    else if(ncreds_out) {
      if(!(data->state.origin->scheme->flags & PROTOPT_USERPWDCTRL) &&
         /* if the protocol cannot handle control codes in credentials, make
            sure there are none */
         (str_has_ctrl(ncreds_out->user) ||
          str_has_ctrl(ncreds_out->passwd))) {
        failf(data, "control code detected in .netrc credentials");
        result = CURLE_READ_ERROR;
        goto out;
      }
      CURL_TRC_M(data, "netrc: using credentials for %s as %s",
                 data->state.origin->hostname, ncreds_out->user);
      result = Curl_creds_merge(ncreds_out->user, ncreds_out->passwd,
                                *pcreds, CREDS_NETRC, pcreds);
      if(result)
        goto out;
      /* for updated strings, we update them in the URL */
      uc = curl_url_set(data->state.uh, CURLUPART_USER,
                        Curl_creds_user(*pcreds), CURLU_URLENCODE);
      if(!uc)
        uc = curl_url_set(data->state.uh, CURLUPART_PASSWORD,
                          Curl_creds_passwd(*pcreds),
                          CURLU_URLENCODE);
      if(uc)
        result = Curl_uc_to_curlcode(uc);
    }
    else
      DEBUGASSERT(0);
  }

#ifdef CURLVERBOSE
  Curl_creds_trace(data, data->state.creds, "transfer credentials");
#endif

out:
  Curl_creds_unlink(&ncreds_out);
  return result;
}
#endif /* CURL_DISABLE_NETRC */

/**
 * @brief Determine the credentials of the transfer.
 * @internal
 *
 * Builds credentials from CURLOPT_* options (when allowed for the origin),
 * else from the URL user and password (URL-decoded, rejecting control
 * codes unless the protocol allows them), then applies netrc. The result
 * is linked into data->state.creds if it changed.
 *
 * @param[in,out] data  transfer, state.creds is updated.
 * @param[in]     uh    parsed URL to read user and password from.
 * @return CURLE_OK on success
 * @retval CURLE_BAD_FUNCTION_ARGUMENT control code in option credentials.
 * @retval CURLE_OUT_OF_MEMORY or another conversion/netrc error.
 */
static CURLcode url_set_data_creds(struct Curl_easy *data, CURLU *uh)
{
  struct Curl_creds *newcreds = NULL;
  CURLcode result = CURLE_OK;

  if((CURL_EASY_STR(data, STRING_USERNAME) ||
      CURL_EASY_STR(data, STRING_PASSWORD) ||
      CURL_EASY_STR(data, STRING_BEARER) ||
      CURL_EASY_STR(data, STRING_SASL_AUTHZID) ||
      CURL_EASY_STR(data, STRING_SERVICE_NAME)) &&
     Curl_auth_allowed_to_origin(data, data->state.origin)) {
    result = Curl_creds_create(CURL_EASY_STR(data, STRING_USERNAME),
                               CURL_EASY_STR(data, STRING_PASSWORD),
                               CURL_EASY_STR(data, STRING_BEARER),
                               CURL_EASY_STR(data, STRING_SASL_AUTHZID),
                               CURL_EASY_STR(data, STRING_SERVICE_NAME),
                               CREDS_OPTION, &newcreds);
    if(result)
      goto out;
    if(newcreds &&
       !(data->state.origin->scheme->flags & PROTOPT_USERPWDCTRL) &&
       (str_has_ctrl(Curl_creds_user(newcreds)) ||
        str_has_ctrl(Curl_creds_passwd(newcreds)))) {
      /* if the protocol cannot handle control codes in credentials, make
         sure there are none */
      failf(data, "control code detected in credentials");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
  }

  /* Extract credentials from the URL only if there are none OR
   * if no CURLOPT_USER was set. */
  if(!newcreds || !Curl_creds_has_user(newcreds)) {
    char *user = NULL;
    char *passwd = NULL;
    char *udecoded = NULL;
    char *pdecoded = NULL;
    CURLUcode uc;

    uc = curl_url_get(uh, CURLUPART_USER, &user, 0);
    if(uc && (uc != CURLUE_NO_USER))
      result = Curl_uc_to_curlcode(uc);
    if(!result) {
      uc = curl_url_get(uh, CURLUPART_PASSWORD, &passwd, 0);
      if(uc && (uc != CURLUE_NO_PASSWORD))
        result = Curl_uc_to_curlcode(uc);
    }
    if(!result && user) {
      result = Curl_urldecode(user, 0, &udecoded, NULL,
                              (data->state.origin->scheme->flags &
                               PROTOPT_USERPWDCTRL) ?
                              REJECT_ZERO : REJECT_CTRL);
    }
    if(!result && passwd) {
      result = Curl_urldecode(passwd, 0, &pdecoded, NULL,
                              (data->state.origin->scheme->flags &
                               PROTOPT_USERPWDCTRL) ?
                              REJECT_ZERO : REJECT_CTRL);
    }
    if(!result)
      result = Curl_creds_merge(udecoded, pdecoded, newcreds,
                                CREDS_URL, &newcreds);

    curlx_free(udecoded);
    curlx_free(pdecoded);
    curlx_free(passwd);
    curlx_free(user);
    if(result) {
      failf(data, "error extracting credentials from URL");
      goto out;
    }
  }

#ifndef CURL_DISABLE_NETRC
  /* Check for overridden login details and set them accordingly so that
     they are known when protocol->setup_connection is called! */
  result = url_set_data_creds_netrc(data, &newcreds);
#endif /* CURL_DISABLE_NETRC */

out:
  if(!result && !Curl_creds_equal(data->state.creds, newcreds)) {
    /* Do we have more things to trigger on credentials change? */
    Curl_creds_link(&data->state.creds, newcreds);
  }
  Curl_creds_unlink(&newcreds);
  return result;
}

/**
 * @brief Set origin, scheme and options of a connection from the transfer.
 * @internal
 *
 * @param[in]     data  transfer with state.origin and url pieces.
 * @param[in,out] conn  (needle) connection to fill.
 * @return CURLE_OK on success, the error of url_set_conn_scheme(), or
 * @retval CURLE_OUT_OF_MEMORY when copying the login options fails.
 */
static CURLcode url_set_conn_origin_etc(struct Curl_easy *data,
                                        struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  Curl_peer_link(&conn->origin, data->state.origin);

  /* set the connection scheme */
  result = url_set_conn_scheme(data, conn);
  if(result)
    goto out;

  /* set the connection options */
  if(CURL_EASY_STR(data, STRING_OPTIONS)) {
    conn->options = curlx_strdup(CURL_EASY_STR(data, STRING_OPTIONS));
    if(!conn->options) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }
  else if(data->state.up.options) {
    conn->options = curlx_strdup(data->state.up.options);
    if(!conn->options) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

out:
  return result;
}

/**
 * @brief Prepare a ranged or resumed transfer.
 *
 * If we are doing a resumed transfer (or CURLOPT_RANGE is set), builds
 * the range string and enables use_range, otherwise disables it.
 *
 * @param[in,out] data  transfer, state.range and state.use_range change.
 * @return CURLE_OK on success
 * @retval CURLE_OUT_OF_MEMORY the range string could not be allocated.
 * @post state.rangestringalloc is TRUE when a range string was allocated.
 */
static CURLcode setup_range(struct Curl_easy *data)
{
  struct UrlState *s = &data->state;
  s->resume_from = data->set.set_resume_from;
  if(s->resume_from || CURL_EASY_STR(data, STRING_SET_RANGE)) {
    if(s->rangestringalloc)
      curlx_free(s->range);

    if(s->resume_from)
      s->range = curl_maprintf("%" FMT_OFF_T "-", s->resume_from);
    else
      s->range = curlx_strdup(CURL_EASY_STR(data, STRING_SET_RANGE));

    if(!s->range)
      return CURLE_OUT_OF_MEMORY;

    s->rangestringalloc = TRUE;

    /* tell ourselves to fetch this range */
    s->use_range = TRUE;        /* enable range download */
  }
  else
    s->use_range = FALSE; /* disable range download */

  return CURLE_OK;
}

/**
 * @brief Set up protocol specific connection internals.
 * @internal
 *
 * Calls the scheme's setup_connection handler, then builds the lowercased
 * "host:port" destination string ("[v6%scope]:port" for IPv6) and the
 * IPv6 scope id. Initialized before the connection is made.
 *
 * @param[in]     data  transfer.
 * @param[in,out] conn  connection, conn->destination and scope_id are set.
 * @return CURLE_OK on success
 * @retval CURLE_FAILED_INIT no destination peer could be determined.
 * @retval CURLE_OUT_OF_MEMORY destination string allocation failed.
 * @retval other error from the protocol setup_connection handler.
 * @pre Must be called after proxy magic has been figured out.
 */
static CURLcode setup_connection_internals(struct Curl_easy *data,
                                           struct connectdata *conn)
{
  struct Curl_peer *peer = NULL;

  if(conn->scheme->run->setup_connection) {
    CURLcode result = conn->scheme->run->setup_connection(data, conn);
    if(result)
      return result;
  }

  /* Now create the destination name */
  peer = Curl_conn_get_destination(conn, FIRSTSOCKET);
  if(!peer)
    return CURLE_FAILED_INIT;

  /* IPv6 addresses with a scope_id (0 is default == global) have a
   * printable representation with a '%<scope_id>' suffix. */
  if(peer->ipv6)
    if(peer->scopeid)
      conn->destination = curl_maprintf("[%s%%%u]:%u",
        peer->hostname, peer->scopeid, peer->port);
    else
      conn->destination = curl_maprintf("[%s]:%u",
        peer->hostname, peer->port);
  else
    conn->destination = curl_maprintf("%s:%u", peer->hostname, peer->port);
  if(!conn->destination)
    return CURLE_OUT_OF_MEMORY;

  Curl_strntolower(conn->destination, conn->destination,
                   strlen(conn->destination));

#ifdef USE_IPV6
  if(data->set.scope_id)
    conn->scope_id = data->set.scope_id;
  else {
    peer = Curl_conn_get_first_peer(conn, FIRSTSOCKET);
    if(!peer)
      return CURLE_FAILED_INIT;
    conn->scope_id = peer->scopeid;
  }
#endif

  return CURLE_OK;
}

/**
 * @brief Split a login string into user, password and options.
 *
 * Supported formats:
 * @code
 *   user
 *   user:password
 *   user:password;options
 *   user;options
 *   user;options:password
 *   :password
 *   :password;options
 *   ;options
 *   ;options:password
 * @endcode
 *
 * @param[in]  login     login string (not necessarily NUL terminated).
 * @param[in]  len       length of @p login.
 * @param[out] userp     receives newly allocated user (may be empty).
 * @param[out] passwdp   receives newly allocated password or NULL if absent.
 * @param[out] optionsp  OPTIONAL, receives newly allocated options or NULL.
 *                       When NULL, ';' is not treated as a separator.
 * @return CURLE_OK on success
 * @retval CURLE_OUT_OF_MEMORY allocation failed, outputs are untouched.
 * @post The caller frees *userp, *passwdp and *optionsp with curlx_free().
 */
CURLcode Curl_parse_login_details(const char *login, const size_t len,
                                  char **userp, char **passwdp,
                                  char **optionsp)
{
  char *ubuf = NULL;
  char *pbuf = NULL;
  const char *psep = NULL;
  const char *osep = NULL;
  size_t ulen;
  size_t plen;
  size_t olen;

  DEBUGASSERT(userp);
  DEBUGASSERT(passwdp);

  /* Attempt to find the password separator */
  psep = memchr(login, ':', len);

  /* Attempt to find the options separator */
  if(optionsp)
    osep = memchr(login, ';', len);

  /* Calculate the portion lengths */
  ulen = (psep ?
          (size_t)(osep && psep > osep ? osep - login : psep - login) :
          (osep ? (size_t)(osep - login) : len));
  plen = (psep ?
          (osep && osep > psep ? (size_t)(osep - psep) :
           (size_t)(login + len - psep)) - 1 : 0);
  olen = (osep ?
          (psep && psep > osep ? (size_t)(psep - osep) :
           (size_t)(login + len - osep)) - 1 : 0);

  /* Clone the user portion buffer, which can be zero length */
  ubuf = curlx_memdup0(login, ulen);
  if(!ubuf)
    goto error;

  /* Clone the password portion buffer */
  if(psep) {
    pbuf = curlx_memdup0(&psep[1], plen);
    if(!pbuf)
      goto error;
  }

  /* Allocate the options portion buffer */
  if(optionsp) {
    char *obuf = NULL;
    if(olen) {
      obuf = curlx_memdup0(&osep[1], olen);
      if(!obuf)
        goto error;
    }
    *optionsp = obuf;
  }
  *userp = ubuf;
  *passwdp = pbuf;
  return CURLE_OK;
error:
  curlx_free(ubuf);
  curlx_free(pbuf);
  return CURLE_OUT_OF_MEMORY;
}

/**
 * @brief Set the login details so they are available in the connection.
 * @internal
 *
 * Protocols that need a password get default credentials if none exist;
 * protocols that do not take credentials per request inherit those of the
 * transfer.
 *
 * @param[in]     data  transfer with state.creds and origin.
 * @param[in,out] conn  connection, creds and creds_origin are set.
 * @return CURLE_OK, or the error of Curl_creds_create() (out of memory).
 */
static CURLcode url_set_conn_login(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  /* If our protocol needs a password and we have none, use the defaults */
  if((conn->scheme->flags & PROTOPT_NEEDSPWD) && !conn->creds) {
    Curl_peer_link(&conn->creds_origin, data->state.origin);
    if(data->state.creds)
      Curl_creds_link(&conn->creds, data->state.creds);
    else
      return Curl_creds_create(CURL_DEFAULT_USER, CURL_DEFAULT_PASSWORD,
                               NULL, NULL, NULL, CREDS_NONE, &conn->creds);
  }
  else if(!(conn->scheme->flags & PROTOPT_CREDSPERREQUEST)) {
    /* for protocols that do not handle credentials per request,
     * the connection credentials are set by the initial transfer. */
    Curl_peer_link(&conn->creds_origin, data->state.origin);
    Curl_creds_link(&conn->creds, data->state.creds);
  }

  return CURLE_OK;
}

/**
 * @brief Parse one "connect to" string.
 * @internal
 *
 * Parses "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT". An empty HOST or
 * PORT matches anything. If both match the destination, the remainder
 * is turned into a peer.
 *
 * @param[in]  data          transfer.
 * @param[in]  dest          origin peer of the request.
 * @param[in]  conn_to_line  the entry from CURLOPT_CONNECT_TO.
 * @param[out] pvia_dest     new peer to connect to, or NULL if no match.
 * @return CURLE_OK, or the error of Curl_peer_from_connect_to().
 */
static CURLcode parse_connect_to_string(struct Curl_easy *data,
                                        const struct Curl_peer *dest,
                                        const char *conn_to_line,
                                        struct Curl_peer **pvia_dest)
{
  CURLcode result = CURLE_OK;
  const char *ptr = conn_to_line;
  bool host_match = FALSE;
  bool port_match = FALSE;

  *pvia_dest = NULL;

  if(*ptr == ':') {
    /* an empty hostname always matches */
    host_match = TRUE;
    ptr++;
  }
  else {
    /* check whether the URL's hostname matches. Use the URL hostname
     * when it was an IPv6 address. Otherwise use the connection's hostname
     * that has IDN conversion. */
    size_t hlen = strlen(dest->hostname);
    host_match = curl_strnequal(ptr, dest->hostname, hlen);
    if(!host_match && (dest->user_hostname != dest->hostname)) {
      /* hostname was normalized, could be IPv6 or IDN */
      hlen = strlen(dest->user_hostname);
      host_match = curl_strnequal(ptr, dest->user_hostname, hlen);
    }
    host_match = host_match && ptr[hlen] == ':';
    if(host_match)
      ptr += hlen + 1;
  }

  if(host_match) {
    if(*ptr == ':') {
      /* an empty port always matches */
      port_match = TRUE;
      ptr++;
    }
    else {
      /* check whether the URL's port matches */
      const char *ptr_next = strchr(ptr, ':');
      if(ptr_next) {
        curl_off_t port_to_match;
        if(!curlx_str_number(&ptr, &port_to_match, 0xffff) &&
           ((uint16_t)port_to_match == dest->port)) {
          port_match = TRUE;
        }
        ptr = ptr_next + 1;
      }
    }
  }

  if(host_match && port_match && ptr && *ptr)
    result = Curl_peer_from_connect_to(data, dest, ptr, pvia_dest);

  return result;
}

/**
 * @brief Decide whether to connect to the origin directly or via a peer.
 * @internal
 *
 * With `conn->origin` known, determine if we should talk to that directly
 * or via another peer. This is the result of inspecting the "connect to"
 * slist and "alt-svc" settings. An Alt-Svc hit may also change the wanted
 * HTTP versions and the transport (QUIC).
 *
 * @param[in]     data  transfer.
 * @param[in,out] conn  connection, conn->via_peer may be set.
 * @return CURLE_OK, or the error from parsing or peer creation.
 * @pre conn->via_peer is NULL.
 */
static CURLcode url_set_conn_peer(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct Curl_peer *origin = conn->origin;
  struct Curl_peer *via_peer = NULL;
  struct curl_slist *conn_to_entry = data->set.connect_to;

  DEBUGASSERT(!conn->via_peer);
  Curl_peer_unlink(&conn->via_peer);

  while(conn_to_entry && !via_peer) {
    result = parse_connect_to_string(data, origin, conn_to_entry->data,
                                     &via_peer);
    if(result)
      return result;
    conn_to_entry = conn_to_entry->next;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(data->asi && !via_peer &&
     ((conn->scheme->protocol == CURLPROTO_HTTPS) ||
#ifdef DEBUGBUILD
      /* allow debug builds to circumvent the HTTPS restriction */
      getenv("CURL_ALTSVC_HTTP")
#else
      0
#endif
       )) {
    /* no connect_to match, try alt-svc! */
    enum alpnid srcalpnid = ALPN_none;
    bool hit = FALSE;
    struct altsvc *as = NULL;
    int allowed_alpns = ALPN_none;
    struct http_negotiation *neg = &data->state.http_neg;
    bool same_dest = FALSE;

    DEBUGF(infof(data, "Alt-svc check wanted=%x, allowed=%x",
                 neg->wanted, neg->allowed));
#ifdef USE_HTTP3
    if(neg->allowed & CURL_HTTP_V3x)
      allowed_alpns |= ALPN_h3;
#endif
#ifdef USE_HTTP2
    if(neg->allowed & CURL_HTTP_V2x)
      allowed_alpns |= ALPN_h2;
#endif
    if(neg->allowed & CURL_HTTP_V1x)
      allowed_alpns |= ALPN_h1;
    allowed_alpns &= (int)data->asi->flags;

    DEBUGF(infof(data, "check Alt-Svc for host '%s'", origin->hostname));
#ifdef USE_HTTP3
    if(!hit && (neg->wanted & CURL_HTTP_V3x)) {
      srcalpnid = ALPN_h3;
      hit = Curl_altsvc_lookup(data->asi,
                               origin, ALPN_h3, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }
#endif
#ifdef USE_HTTP2
    if(!hit && (neg->wanted & CURL_HTTP_V2x) &&
       !neg->h2_prior_knowledge) {
      srcalpnid = ALPN_h2;
      hit = Curl_altsvc_lookup(data->asi,
                               origin, ALPN_h2, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }
#endif
    if(!hit && (neg->wanted & CURL_HTTP_V1x) &&
       !neg->only_10) {
      srcalpnid = ALPN_h1;
      hit = Curl_altsvc_lookup(data->asi,
                               origin, ALPN_h1, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }

    if(hit && same_dest) {
      /* same destination, but more HTTPS version options */
      switch(as->dst.alpnid) {
      case ALPN_h1:
        neg->wanted |= CURL_HTTP_V1x;
        neg->preferred = CURL_HTTP_V1x;
        break;
      case ALPN_h2:
        neg->wanted |= CURL_HTTP_V2x;
        neg->preferred = CURL_HTTP_V2x;
        break;
      case ALPN_h3:
        neg->wanted |= CURL_HTTP_V3x;
        neg->preferred = CURL_HTTP_V3x;
        break;
      default: /* should not be possible */
        break;
      }
    }
    else if(hit) {
      result = Curl_peer_create(data, conn->origin->scheme,
                                as->dst.host, as->dst.port,
                                &via_peer);
      if(result)
        return result;
      infof(data, "Alt-svc connecting from [%s]%s:%u to [%s]%s:%u",
            Curl_alpnid2str(srcalpnid), origin->hostname, origin->port,
            Curl_alpnid2str(as->dst.alpnid),
            via_peer->hostname, via_peer->port);
      conn->bits.altused = TRUE;
      if(srcalpnid != as->dst.alpnid) {
        /* protocol version switch */
        switch(as->dst.alpnid) {
        case ALPN_h1:
          neg->wanted = neg->allowed = CURL_HTTP_V1x;
          neg->only_10 = FALSE;
          break;
        case ALPN_h2:
          neg->wanted = neg->allowed = CURL_HTTP_V2x;
          break;
        case ALPN_h3:
          conn->transport_wanted = TRNSPRT_QUIC;
          neg->wanted = neg->allowed = CURL_HTTP_V3x;
          break;
        default: /* should not be possible */
          break;
        }
      }
    }
  }
#endif

  if(via_peer)
    conn->via_peer = via_peer;

  return result;
}

/**
 * @brief Adjust a reused connection to the transfer's needle.
 * @internal
 *
 * Copies credentials, proxy credentials and the origin/via peers from the
 * needle to the reused connection, since matching does not require the
 * origin to be identical (proxy without tunnel, connect-to).
 *
 * @param[in,out] data    transfer, data->conn is the reused connection.
 * @param[in]     needle  prototype connection of this transfer.
 */
static void url_conn_reuse_adjust(struct Curl_easy *data,
                                  struct connectdata *needle)
{
  struct connectdata *conn = data->conn;

  /* get the user+password information from the needle since it may
   * be new for this request even when we reuse conn */
  if(needle->creds) {
    /* use the new username and password though */
    Curl_creds_link(&conn->creds, needle->creds);
  }

#ifndef CURL_DISABLE_PROXY
  /* use the new proxy username and proxy password though */
  Curl_creds_link(&conn->http_proxy.creds, needle->http_proxy.creds);
  Curl_creds_link(&conn->socks_proxy.creds, needle->socks_proxy.creds);
#endif

  /* Finding a connection for reuse in the cpool matches, among other
   * things on the "remote-relevant" hostname. This is not necessarily
   * the authority of the URL, e.g. conn->origin. For example:
   * - we use a proxy (not tunneling). we want to send all requests
   *   that use the same proxy on this connection.
   * - we have a "connect-to" setting that may redirect the hostname of
   *   a new request to the same remote endpoint of an existing conn.
   *   We want to reuse an existing conn to the remote endpoint.
   * Since connection reuse does not match on conn->origin necessarily, we
   * switch conn to needle's host settings.
   */
  Curl_peer_link(&conn->origin, needle->origin);
  Curl_peer_link(&conn->via_peer, needle->via_peer);
  Curl_peer_link(&conn->origin2, needle->origin2);
  Curl_peer_link(&conn->via_peer2, needle->via_peer2);
}

/**
 * @brief Destructor callback for conn->meta_hash entries.
 * @internal
 *
 * Same contract as easy_meta_freeentry(): never called as entries must
 * bring their own destructor.
 *
 * @param[in] p  stored element (unused, asserted to be NULL).
 */
static void conn_meta_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(!p);
}

/**
 * @brief Create the template ("needle") connection for a transfer.
 * @internal
 *
 * Allocates a connection and fills in origin, scheme, unix socket or
 * connect-to/alt-svc peer, proxy, login, protocol internals and I/O
 * callbacks, so it can be compared with pooled connections or become the
 * connection used.
 *
 * @param[in]  data     transfer.
 * @param[out] pneedle  receives the needle on success, NULL on failure.
 * @return CURLE_OK on success, otherwise the first error met
 *         (CURLE_OUT_OF_MEMORY, CURLE_UNSUPPORTED_PROTOCOL, ...).
 * @post On failure the partially built connection has been freed.
 */
static CURLcode url_create_needle(struct Curl_easy *data,
                                  struct connectdata **pneedle)
{
  struct connectdata *needle = NULL;
  CURLcode result = CURLE_OK;
  bool network_scheme = TRUE; /* almost all are */

  /* Allocate a temporary connection data struct (needle) and fill in for
     comparison purposes. */
  needle = allocate_conn(data);
  if(!needle) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* Do the unfailable inits first, before checks that may early return */
  Curl_hash_init(&needle->meta_hash, 23, CURL_HASH_TYPE_BYTES,
                 conn_meta_freeentry);

  /*************************************************************
   * Determine `conn->origin` and populate `data->state.up` and
   * other URL related properties.
   *************************************************************/
  result = url_set_conn_origin_etc(data, needle);
  if(result)
    goto out;

  DEBUGASSERT(needle->origin);
  network_scheme = !(needle->origin->scheme->flags & PROTOPT_NONETWORK);

#ifdef USE_UNIX_SOCKETS
  /*************************************************************
   * Set UDS first. It overrides "via_peer" and proxy settings.
   *************************************************************/
  if(network_scheme && CURL_EASY_STR(data, STRING_UNIX_SOCKET_PATH)) {
    result = Curl_peer_uds_create(
      needle->origin->scheme, CURL_EASY_STR(data, STRING_UNIX_SOCKET_PATH),
      (bool)data->set.abstract_unix_socket, &needle->via_peer);
    if(result)
      goto out;
  }
#endif /* USE_UNIX_SOCKETS */

  if(network_scheme && !needle->via_peer) {
    /*************************************************************
     * If the `via_peer` is not already set (via UDS above),
     * determine if we talk to `conn->origin` directly or use
     * `conn->via_peer` using "connect to" and "alt-svc" properties.
     *************************************************************/
    result = url_set_conn_peer(data, needle);
    if(result)
      goto out;
  }

  /*************************************************************
   * Check whether the host and the "connect to host" are equal.
   * Do this after the hostnames have been IDN-converted and
   * before initializing the proxy.
   *************************************************************/
  if(Curl_peer_equal(needle->origin, needle->via_peer)) {
    Curl_peer_unlink(&needle->via_peer);
  }

#ifndef CURL_DISABLE_PROXY
  /* Going via a unix socket ignores any proxy settings */
  if(network_scheme &&
     (!needle->via_peer || !needle->via_peer->unix_socket)) {
    result = Curl_proxy_init_conn(data, needle);
    if(result)
      goto out;
  }
#endif /* CURL_DISABLE_PROXY */

  result = url_set_conn_login(data, needle); /* default credentials */
  if(result)
    goto out;

  /*************************************************************
   * Setup internals depending on protocol. Needs to be done after
   * we figured out what/if proxy to use.
   *************************************************************/
  result = setup_connection_internals(data, needle);
  if(result)
    goto out;

  if(needle->scheme->flags & PROTOPT_ALPN) {
    /* The protocol wants it, so set the bits if enabled in the easy handle
       (default) */
    if(data->set.ssl_enable_alpn)
      needle->bits.tls_enable_alpn = TRUE;
  }

  if(network_scheme) {
    /* Setup callbacks for network connections */
    needle->recv[FIRSTSOCKET] = Curl_cf_recv;
    needle->send[FIRSTSOCKET] = Curl_cf_send;
    needle->recv[SECONDARYSOCKET] = Curl_cf_recv;
    needle->send[SECONDARYSOCKET] = Curl_cf_send;
    needle->bits.tcp_fastopen = data->set.tcp_fastopen;
#ifdef USE_UNIX_SOCKETS
    if(Curl_conn_get_first_peer(needle, FIRSTSOCKET)->unix_socket)
      needle->transport_wanted = TRNSPRT_UNIX;
#endif
  }

out:
  if(!result) {
    DEBUGASSERT(needle);
    DEBUGASSERT(needle->origin);
    *pneedle = needle;
  }
  else {
    *pneedle = NULL;
    if(needle)
      Curl_conn_free(data, needle);
  }
  return result;
}

/**
 * @brief Parse the transfer URL and set origin, URL pieces and credentials.
 * @internal
 *
 * Duplicates or creates the CURLU handle, applies the default protocol if
 * the URL has no scheme, normalizes the URL, derives the origin peer (with
 * HSTS upgrade), remembers the initial origin, extracts path, query and
 * options, and finally determines credentials.
 *
 * @param[in,out] data  transfer, state.url/up/uh/origin/creds are updated.
 * @return CURLE_OK on success
 * @retval CURLE_URL_MALFORMAT no URL set or it is malformed.
 * @retval CURLE_OUT_OF_MEMORY allocation failure.
 * @retval other conversion of URL API errors, peer or credential errors.
 */
static CURLcode url_set_data_origin_and_creds(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  CURLU *uh;
  CURLUcode uc = CURLUE_OK;
  bool use_set_uh = (data->set.uh && !data->state.this_is_a_follow);
  uint16_t port_override = data->state.allow_port ? data->set.use_port : 0;
  uint32_t scope_id = 0;

  /*************************************************************
   * Check input data
   *************************************************************/
  if(!Curl_bufref_ptr(&data->state.url)) {
    result = CURLE_URL_MALFORMAT;
    goto out;
  }

  up_free(data); /* cleanup previous leftovers first */

  /* parse the URL */
  if(use_set_uh)
    uh = data->state.uh = curl_url_dup(data->set.uh);
  else
    uh = data->state.uh = curl_url();
  if(!uh) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!use_set_uh) {
    bool prepend_sheme = FALSE;
    /* special-case when 'file' is default as a normal path is not a valid URL
       without the 'file' scheme present */
    if(curl_strequal("file", CURL_EASY_STR(data, STRING_DEFAULT_PROTOCOL)) &&
       !Curl_is_absolute_url(Curl_bufref_ptr(&data->state.url), NULL, 0, TRUE))
      prepend_sheme = TRUE;
    else {
      uc = curl_url_set(uh, CURLUPART_URL, Curl_bufref_ptr(&data->state.url),
                        (unsigned int)
                        CURLU_GUESS_SCHEME |
                        CURLU_NON_SUPPORT_SCHEME |
                        (data->set.disallow_username_in_url ?
                         CURLU_DISALLOW_USER : 0) |
                        (data->set.path_as_is ? CURLU_PATH_AS_IS : 0));
      if(uc) {
        failf(data, "URL rejected: %s", curl_url_strerror(uc));
        result = Curl_uc_to_curlcode(uc);
        goto out;
      }

      if(CURL_EASY_STR(data, STRING_DEFAULT_PROTOCOL)) {
        /* check if we there was a scheme provided */
        char *scheme;
        uc = curl_url_get(uh, CURLUPART_SCHEME, &scheme,
                          CURLU_NO_GUESS_SCHEME);
        if(uc == CURLUE_NO_SCHEME)
          prepend_sheme = TRUE;
        curl_free(scheme);
        if(uc && uc != CURLUE_NO_SCHEME) {
          result = Curl_uc_to_curlcode(uc);
          goto out;
        }
      }
    }

    if(prepend_sheme) {
      char *url = curl_maprintf("%s://%s",
                                CURL_EASY_STR(data, STRING_DEFAULT_PROTOCOL),
                                Curl_bufref_ptr(&data->state.url));
      if(!url) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      uc = curl_url_set(uh, CURLUPART_URL, url,
                        (unsigned int)
                        CURLU_GUESS_SCHEME |
                        CURLU_NON_SUPPORT_SCHEME |
                        (data->set.disallow_username_in_url ?
                         CURLU_DISALLOW_USER : 0) |
                        (data->set.path_as_is ? CURLU_PATH_AS_IS : 0));
      curl_free(url);
      if(uc) {
        failf(data, "URL rejected: %s", curl_url_strerror(uc));
        result = Curl_uc_to_curlcode(uc);
        goto out;
      }
    }
    {
      char *newurl;
      /* after it was parsed, and possibly given a new scheme, get the
         normalized version */
      uc = curl_url_get(uh, CURLUPART_URL, &newurl, CURLU_GET_EMPTY);
      if(uc) {
        result = Curl_uc_to_curlcode(uc);
        goto out;
      }
      if(prepend_sheme)
        infof(data, "Applied default protocol '%s'",
              CURL_EASY_STR(data, STRING_DEFAULT_PROTOCOL));
      Curl_bufref_set(&data->state.url, newurl, 0, curl_free);
    }
  }

#ifdef USE_IPV6
  scope_id = data->set.scope_id;
#endif

  /* `uh` is now as the connection should use it, probably. */
  result = Curl_peer_from_url(uh, data, port_override, scope_id,
                              &data->state.origin);
  if(result)
    goto out;
  /* The origin might get changed when HSTS applies */
  result = hsts_upgrade(data, uh, port_override, scope_id);
  if(result)
    goto out;

  /* When the transfers initial_origin is not set, this is the initial
   * request. Remember this starting point. */
  if(!data->state.initial_origin)
    Curl_peer_link(&data->state.initial_origin, data->state.origin);

  uc = curl_url_get(uh, CURLUPART_PATH, &data->state.up.path, CURLU_URLENCODE);
  if(uc) {
    result = Curl_uc_to_curlcode(uc);
    goto out;
  }
  uc = curl_url_get(uh, CURLUPART_QUERY, &data->state.up.query,
                    CURLU_GET_EMPTY);
  if(uc && (uc != CURLUE_NO_QUERY)) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  uc = curl_url_get(uh, CURLUPART_OPTIONS, &data->state.up.options,
                    CURLU_URLDECODE);
  if(uc && (uc != CURLUE_NO_OPTIONS)) {
    result = Curl_uc_to_curlcode(uc);
    goto out;
  }

  result = url_set_data_creds(data, uh);
  if(result)
    goto out;

out:
  return result;
}

/**
 * @brief Initialize the match state for a connection search.
 * @internal
 *
 * Zeroes @p m, records transfer, needle and time, derives multiplex and
 * Negotiate wishes, TLS requirements and a shallow SSL config.
 *
 * @param[in]  data    transfer.
 * @param[in]  needle  template connection.
 * @param[out] m       match state to fill.
 * @return CURLE_OK, or the error of the SSL filter config setup.
 * @post Release with url_match_destroy() when the call succeeded.
 */
static CURLcode url_match_init(struct Curl_easy *data,
                               struct connectdata *needle,
                               struct url_conn_match *m)
{
  memset(m, 0, sizeof(*m));
  m->data = data;
  m->needle = needle;
  m->now = *Curl_pgrs_now(data);
  m->may_multiplex = xfer_may_multiplex(data, needle);

#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)
  m->want_nego_http =
    (data->state.authhost.want & CURLAUTH_NEGOTIATE) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP) &&
    Curl_auth_allowed_to_host(data);
#ifndef CURL_DISABLE_PROXY
  m->want_proxy_nego_http =
    needle->http_proxy.creds &&
    (data->state.authproxy.want & CURLAUTH_NEGOTIATE) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP);
#endif
#endif
  m->require_tls = data->set.use_ssl >= CURLUSESSL_CONTROL;
  m->may_tls = data->set.use_ssl > CURLUSESSL_NONE;

  /* Get a shallow setup of filter configs for connection cache matching */
  return Curl_ssl_filter_config_tmp_init(data, needle->origin,
                                         &m->ssl_config,
#ifndef CURL_DISABLE_PROXY
                                         &m->proxy_ssl_config);
#else
                                         NULL);
#endif
}

/**
 * @brief Release the SSL configs held by a match state.
 * @internal
 *
 * @param[in,out] m  match state previously set up by url_match_init().
 */
static void url_match_destroy(struct url_conn_match *m)
{
  Curl_ssl_config_cleanup(&m->ssl_config);
#ifndef CURL_DISABLE_PROXY
  Curl_ssl_config_cleanup(&m->proxy_ssl_config);
#endif
}

/**
 * @brief Find an existing connection for the transfer or create a new one.
 * @internal
 *
 * Builds the needle, handles the no-network case (file:), tries to reuse
 * a pooled connection unless fresh connects are requested, else adds the
 * needle to the pool within the connection limits. Then prepares the
 * transfer, range and connection filters.
 *
 * @param[in,out] data  transfer, data->conn is set on success.
 * @param[in]     pnow  current time.
 * @return CURLE_OK on success with a connection attached to data
 * @retval CURLE_NO_CONNECTION_AVAILABLE connection limits apply or a
 *         suitable connection has not determined its multiplex capability.
 * @retval other a fatal error.
 * @post On error data->conn may be unset and the needle is freed.
 */
static CURLcode url_find_or_create_conn(struct Curl_easy *data,
                                        const struct curltime *pnow)
{
  struct connectdata *needle = NULL;
  struct url_conn_match match;
  bool match_initialized = FALSE;
  CURLcode result;

  /* create the template connection for transfer data. Use this needle to
   * find an existing connection or, if none exists, convert needle
   * to a full connection and attach it to data. */
  result = url_create_needle(data, &needle);
  if(result)
    goto out;
  DEBUGASSERT(needle);

  result = url_match_init(data, needle, &match);
  if(result)
    goto out;
  match_initialized = TRUE;

  /***********************************************************************
   * file: is a special case in that it does not need a network connection
   ***********************************************************************/
#ifndef CURL_DISABLE_FILE
  if(needle->scheme->flags & PROTOPT_NONETWORK) {
    bool done;
    /* this is supposed to be the connect function so we better at least check
       that the file is present here! */
    DEBUGASSERT(needle->scheme->run->connect_it);
    data->info.conn_scheme = needle->scheme->name;
    /* conn_protocol can only provide "old" protocols */
    data->info.conn_protocol = needle->scheme->protocol & CURLPROTO_MASK;
    result = needle->scheme->run->connect_it(data, &done);
    if(result)
      goto out;

    /* Setup a "faked" transfer that will do nothing */
    result = Curl_cpool_add(data, needle, 0, 0, pnow);
    Curl_attach_connection(data, needle, TRUE);
    needle = NULL;
    if(!result) {
      /* Setup whatever necessary for a resumed transfer */
      result = setup_range(data);
      if(!result) {
        Curl_xfer_setup_nop(data);
        result = Curl_init_transfer(data, data->conn);
      }
    }

    if(result) {
      DEBUGASSERT(data->conn->scheme->run->done);
      /* we ignore the return code for the protocol-specific DONE */
      (void)data->conn->scheme->run->done(data, result, FALSE);
    }
    goto out;
  }
#endif

  /*************************************************************
   * Reuse of existing connection is not allowed when
   * - connect_only is set or
   * - reuse_fresh is set and this is not a follow-up request
   *   (like with HTTP followlocation)
   *************************************************************/
  if((!data->set.reuse_fresh || data->state.followlocation) &&
     !data->set.connect_only) {
    /* Ok, try to find and attach an existing one */
    if(url_attach_existing(data, needle, &match, pnow)) {
      /* We attached an existing connection for this transfer. Copy
       * over transfer specific properties over from needle. */
      struct connectdata *conn = data->conn;
      VERBOSE(bool tls_upgraded =
        (!(needle->origin->scheme->flags & PROTOPT_SSL) &&
         Curl_conn_is_ssl(conn, FIRSTSOCKET)));

      DEBUGASSERT(conn);
      conn->bits.reuse = TRUE;
      url_conn_reuse_adjust(data, needle);

#ifndef CURL_DISABLE_PROXY
      infof(data, "Reusing existing %s: connection%s with %s %s",
            conn->origin->scheme->name,
            tls_upgraded ? " (upgraded to SSL)" : "",
            (conn->socks_proxy.peer || conn->http_proxy.peer) ?
            "proxy" : "host",
            conn->socks_proxy.peer ? conn->socks_proxy.peer->user_hostname :
            conn->http_proxy.peer ? conn->http_proxy.peer->user_hostname :
            conn->origin->hostname);
#else
      infof(data, "Reusing existing %s: connection%s with host %s",
            conn->origin->scheme->name,
            tls_upgraded ? " (upgraded to SSL)" : "",
            conn->origin->hostname);
#endif
    }
  }

  if(!data->conn) {
    /* We have not attached an existing connection. `needle` may become
     * the connection to use, if
     * - we are not waiting on an existing connection result
     * - the total/host limits on active connections allow it
     */
    if(match.wait_pipe) {
      /* There is a connection that *might* become usable for multiplexing
         "soon", and we wait for that */
      infof(data, "Waiting on connection to negotiate possible multiplexing.");
      result = CURLE_NO_CONNECTION_AVAILABLE;
      goto out;
    }

    /* Add needle to conn pool, observing the limits.
     * Initializes connection_id.
     * May fail due to limits with CURLE_NO_CONNECTION_AVAILABLE. */
    result = Curl_cpool_add(data, needle,
                            data->multi->max_total_connections,
                            data->multi->max_host_connections,
                            pnow);
    if(result)
      goto out;

    /* All fine, attach it and forget needle */
    Curl_attach_connection(data, needle, TRUE);
    needle = NULL;

    /* Clone the SSL filter configs into the new connection. */
    result = Curl_ssl_conn_config_clone(&match.ssl_config,
#ifndef CURL_DISABLE_PROXY
                                        &match.proxy_ssl_config,
#else
                                        NULL,
#endif
                                        data->conn);
    if(result) {
      DEBUGF(infof(data, "Error: clone connection SSL config"));
      goto out;
    }
  }

  /* COMMON setup code for reused and new connections from here on. */

  /* Setup and init stuff before DO starts, in preparing for the transfer. */
  result = Curl_init_transfer(data, data->conn);
  if(result)
    goto out;

  /* Setup whatever necessary for a resumed transfer */
  result = setup_range(data);
  if(result)
    goto out;

  /* persist the scheme and handler the transfer is using */
  data->info.conn_scheme = data->conn->scheme->name;
  /* conn_protocol can only provide "old" protocols */
  data->info.conn_protocol = data->conn->scheme->protocol & CURLPROTO_MASK;
  data->info.used_proxy =
#ifdef CURL_DISABLE_PROXY
    0
#else
    (data->conn->socks_proxy.peer || data->conn->http_proxy.peer)
#endif
    ;

  /* Lastly, inform connection filters that a new transfer is attached */
  result = Curl_conn_ev_data_setup(data);

out:
  if(match_initialized)
    url_match_destroy(&match);
  if(needle)
    Curl_conn_free(data, needle);
  DEBUGASSERT(result || data->conn);
  return result;
}

/**
 * @brief Start connecting for a transfer.
 *
 * Resets the request, parses the URL and credentials, finds or creates the
 * connection and starts the connection filter setup when it is new.
 *
 * @param[in,out] data        transfer.
 * @param[out]    pconnected  TRUE if the transfer can proceed immediately
 *                            (reused multiplexed or no-network connection).
 * @return CURLE_OK on success (check @p pconnected for state)
 * @retval CURLE_NO_CONNECTION_AVAILABLE try again later.
 * @retval CURLE_FAILED_INIT internal inconsistency.
 * @retval other error from URL parsing, connection setup or headers init.
 * @post On error the connection is detached and closed unless it was reused
 *       or still in use by other transfers.
 */
CURLcode Curl_connect(struct Curl_easy *data, bool *pconnected)
{
  CURLcode result;
  struct connectdata *conn = NULL;
  const struct curltime *pnow = NULL;
  *pconnected = FALSE;

  /* Set the request to virgin state based on transfer settings */
  Curl_req_hard_reset(&data->req, data);
  /* Determine the origin of the transfer and what credentials to use */
  result = url_set_data_origin_and_creds(data);
  if(result)
    goto out;
  if(!data->state.origin) { /* just make really sure */
    DEBUGASSERT(0);
    result = CURLE_FAILED_INIT;
    goto out;
  }

  /* Get or create a connection for the transfer. */
  pnow = Curl_pgrs_now(data);
  Curl_pgrsTimeWas(data, TIMER_POSTQUEUE, *pnow);
  result = url_find_or_create_conn(data, pnow);
  conn = data->conn;
  if(result)
    goto out;
  if(!data->conn) { /* just make really sure */
    DEBUGASSERT(0);
    result = CURLE_FAILED_INIT;
    goto out;
  }

  if(conn->bits.reuse) {
    if(conn->attached_xfers > 1)
      /* multiplexed */
      *pconnected = TRUE;
  }
  else if(conn->scheme->flags & PROTOPT_NONETWORK) {
    Curl_pgrsTime(data, TIMER_NAMELOOKUP);
    *pconnected = TRUE;
  }
  else {
    result = Curl_conn_setup(data, conn, FIRSTSOCKET, CURL_CF_SSL_DEFAULT);
    if(!result)
      result = Curl_headers_init(data);
    CURL_TRC_M(data, "Curl_conn_setup() -> %d", (int)result);
  }

out:
  if(result == CURLE_NO_CONNECTION_AVAILABLE)
    DEBUGASSERT(!conn);

  if(result && conn) {
    /* Detach on error and close the connection if
     * - it was not reused (meaning, ok before we picked it)
     * - there are no other transfers attached to it */
    Curl_detach_connection(data);
    if(!conn->bits.reuse && !CONN_INUSE(conn))
      Curl_conn_close(data, conn, TRUE);
  }

  return result;
}

/**
 * @brief Prepare a transfer, called each time before it starts.
 *
 * Called to prepare for a transfer, sometimes multiple times on the same
 * Curl_easy. Makes sure nothing in here depends on stuff that is setup
 * dynamically for the transfer. Disables wildcard matching for protocols
 * without support and selects HEAD for no-body requests.
 *
 * @param[in,out] data  transfer.
 * @param[in]     conn  connection in use. Allowed to be NULL.
 * @return CURLE_OK on success, else the error from Curl_req_start().
 */
CURLcode Curl_init_transfer(struct Curl_easy *data, struct connectdata *conn)
{
  CURLcode result;

  if(conn) {
    conn->bits.do_more = FALSE; /* by default there is no curl_do_more() to
                                   use */
    /* if the protocol used does not support wildcards, switch it off */
    if(data->state.wildcardmatch &&
       !(conn->scheme->flags & PROTOPT_WILDCARD))
      data->state.wildcardmatch = FALSE;
  }

  data->state.done = FALSE; /* *_done() is not called yet */

  data->req.no_body = data->set.opt_no_body;
  if(data->req.no_body)
    /* in HTTP lingo, no body means using the HEAD request... */
    data->state.httpreq = HTTPREQ_HEAD;

  result = Curl_req_start(&data->req, data);
  if(!result) {
    Curl_pgrsReset(data);
  }
  return result;
}

#if defined(USE_HTTP2) || defined(USE_HTTP3)

/**
 * @brief Reset the HTTP/2 or HTTP/3 stream weight of a transfer.
 *
 * @param[in,out] data  transfer, state.weight is set to 0.
 * @note Only built with HTTP/2 or HTTP/3 support.
 */
void Curl_data_priority_clear_state(struct Curl_easy *data)
{
  data->state.weight = 0;
}

#endif /* USE_HTTP2 || USE_HTTP3 */

/**
 * @brief Attach protocol metadata to a connection under a key.
 *
 * @param[in,out] conn       connection owning the metadata hash.
 * @param[in]     key        NUL terminated key (copied).
 * @param[in]     meta_data  the data. Ownership passes to the connection.
 * @param[in]     meta_dtor  destructor called when removed or on free.
 * @return CURLE_OK on success
 * @retval CURLE_OUT_OF_MEMORY insertion failed. @p meta_dtor was already
 *         called on @p meta_data in that case.
 * @see Curl_conn_meta_get(), Curl_conn_meta_remove()
 */
CURLcode Curl_conn_meta_set(struct connectdata *conn, const char *key,
                            void *meta_data, Curl_meta_dtor *meta_dtor)
{
  if(!Curl_hash_add2(&conn->meta_hash, key, strlen(key) + 1,
                     meta_data, meta_dtor)) {
    meta_dtor(key, strlen(key) + 1, meta_data);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

/**
 * @brief Remove (and destroy) metadata stored under a key.
 *
 * @param[in,out] conn  connection.
 * @param[in]     key   NUL terminated key. Unknown keys are ignored.
 * @warning Calls the destructor, so earlier pointers from
 *          Curl_conn_meta_get() become invalid.
 */
void Curl_conn_meta_remove(struct connectdata *conn, const char *key)
{
  Curl_hash_delete(&conn->meta_hash, key, strlen(key) + 1);
}

/**
 * @brief Look up metadata stored on a connection.
 *
 * @param[in] conn  connection.
 * @param[in] key   NUL terminated key.
 * @return the stored pointer, or NULL if none is set. Owned by the
 *         connection.
 */
void *Curl_conn_meta_get(struct connectdata *conn, const char *key)
{
  return Curl_hash_pick(&conn->meta_hash, key, strlen(key) + 1);
}

/**
 * @brief Get the admin handle responsible for a transfer.
 *
 * Returns the transfer itself if it is the admin handle, else the admin
 * handle of its multi (or of the easy-internal multi). Connection related
 * settings (idle/age limits, timeouts, no_signal) are copied to it.
 *
 * @param[in] data  transfer handle.
 * @return the admin handle, never NULL.
 * @warning The returned handle is owned by the multi handle.
 * @note Having no multi at all is unexpected and asserted in debug builds,
 *       the transfer itself is then returned.
 */
struct Curl_easy *Curl_get_admin(struct Curl_easy *data)
{
  struct Curl_easy *admin;

  if(!data->mid) /* already an admin handle */
    admin = data;
  else if(data->multi)
    admin = data->multi->admin;
  else if(data->multi_easy)
    admin = data->multi_easy->admin;
  else {
    DEBUGASSERT(0); /* we do not want this. does it happen? */
    admin = data;
  }
  if(admin != data) {
    admin->set.conn_max_idle_ms = data->set.conn_max_idle_ms;
    admin->set.conn_max_age_ms = data->set.conn_max_age_ms;
    admin->set.upkeep_interval_ms = data->set.upkeep_interval_ms;
    admin->set.timeout = data->set.timeout;
    admin->set.server_response_timeout = data->set.server_response_timeout;
    admin->set.no_signal = data->set.no_signal;
  }
  return admin;
}

/**
 * @brief Pick the first fatal result of two.
 *
 * CURLE_AGAIN is not considered fatal.
 *
 * @param[in] r1  first result.
 * @param[in] r2  second result.
 * @return @p r1 if it is an error other than CURLE_AGAIN, else @p r2 if it
 *         is such an error, else @p r1.
 */
CURLcode Curl_1st_fatal(CURLcode r1, CURLcode r2)
{
  if(r1 && (r1 != CURLE_AGAIN))
    return r1;
  if(r2 && (r2 != CURLE_AGAIN))
    return r2;
  return r1;
}
