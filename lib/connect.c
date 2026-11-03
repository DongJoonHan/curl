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
 * @brief Connection setup, connect timeouts and connection state helpers.
 *
 * Contains the functions that drive a connection's filter chain to the
 * connected state (Curl_conn_setup(), Curl_conn_connect()), that compute
 * how much time is left for connecting or for the whole transfer, and
 * small accessors for the peers and flags of a struct connectdata.
 *
 * @see cfilters.h, connect.h
 */

#include "curl_setup.h"

#include "urldata.h"
#include "curl_trc.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-https-connect.h"
#include "cf-setup.h"
#include "multiif.h"
#include "progress.h"
#include "conncache.h"
#include "multihandle.h"
#include "select.h"
#include "vdns/cf-dns.h"
#include "curlx/strparse.h"

#if !defined(CURL_DISABLE_ALTSVC) || defined(USE_HTTPSRR)

/**
 * @brief Map an ALPN protocol name to the internal ALPN identifier.
 *
 * Recognizes "h1", "h2" and "h3" as well as "http/1.1" (mapped to h1).
 *
 * @param[in] name Protocol name bytes, not necessarily NUL terminated.
 * @param[in] len  Number of bytes in name.
 * @return ALPN_h1, ALPN_h2 or ALPN_h3 for a known name.
 * @return ALPN_none if the name is unknown.
 * @note Only compiled with alt-svc or HTTPS-RR support.
 */
enum alpnid Curl_alpn2alpnid(const unsigned char *name, size_t len)
{
  if(len == 2) {
    if(!memcmp(name, "h1", 2))
      return ALPN_h1;
    if(!memcmp(name, "h2", 2))
      return ALPN_h2;
    if(!memcmp(name, "h3", 2))
      return ALPN_h3;
  }
  else if(len == 8 && !memcmp(name, "http/1.1", 8))
    return ALPN_h1;
  return ALPN_none; /* unknown, probably rubbish input */
}

#endif

/**
 * @brief Milliseconds left of the connect timeout.
 * @internal
 *
 * Used for connection filters that connect after the transfer left the
 * initial connect phase (e.g. the second FTP socket). The timeout is
 * CURLOPT_CONNECTTIMEOUT_MS or the default, counted from
 * conn->connect_start_ms.
 *
 * @param[in] data Transfer with a connection attached.
 * @param[in] pnow Current time.
 * @return Milliseconds left; negative when expired. A value of exactly 0
 *         is returned as -1 since 0 means "no limit" to callers.
 * @pre data->conn->connect_start_ms >= 0
 */
static timediff_t connect_left_ms(struct Curl_easy *data,
                                  const struct curltime *pnow)
{
  timediff_t timeout_ms = (data->set.connecttimeout > 0) ?
    data->set.connecttimeout : DEFAULT_CONNECT_TIMEOUT;
  timediff_t elapsed_ms =
    curlx_ptimediff_ms(pnow, &data->conn->created) -
    data->conn->connect_start_ms;
  timediff_t left_ms = timeout_ms - elapsed_ms;
  DEBUGASSERT(data->conn->connect_start_ms >= 0);
  return left_ms ? left_ms : -1; /* 0 is "no limit", fake 1 ms expiry */
}

/**
 * @brief Milliseconds left allowed for the transfer/connection.
 * @internal
 *
 * Combines the connect timeout (while connecting) with the overall
 * transfer timeout (CURLOPT_TIMEOUT) and returns the smaller of the two.
 * While the connection is shutting down, the shutdown time limit is used.
 *
 * @param[in] data Transfer.
 * @param[in] pnow Current time.
 * @return 0 if there is no timeout, i.e. infinite time is left.
 * @return A negative value if the timeout time has already elapsed.
 * @return Otherwise the positive number of milliseconds left.
 * @note Exact expiry is reported as -1 to keep it distinct from 0.
 * @unittest 1303
 */
UNITTEST timediff_t timeleft_now_ms(struct Curl_easy *data,
                                    const struct curltime *pnow);
UNITTEST timediff_t timeleft_now_ms(struct Curl_easy *data,
                                    const struct curltime *pnow)
{
  timediff_t timeleft_ms = 0;
  timediff_t ctimeleft_ms = 0;

  if(data->conn && CURL_CONN_IN_SHUTDOWN(data->conn, FIRSTSOCKET))
    return Curl_cshutdn_timeleft_ms(data, data->conn, FIRSTSOCKET);
  else if(Curl_is_connecting(data)) {
    /* transfer has not reached DO phase yet */
    timediff_t ctimeout_ms = (data->set.connecttimeout > 0) ?
      data->set.connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    ctimeleft_ms = ctimeout_ms -
      Curl_pgrs_since_ms(data, pnow, TIMER_STARTSINGLE);
    if(!ctimeleft_ms)
      ctimeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
  }
  else if(data->conn && data->conn->connect_start_ms >= 0) {
    /* ongoing connect of filters, pbly FTP second socket */
    ctimeleft_ms = connect_left_ms(data, pnow);
  }
  else if(!data->set.timeout || data->set.connect_only) {
    return 0; /* no timeout in place or checked, return "no limit" */
  }

  if(data->set.timeout) {
    timeleft_ms = data->set.timeout -
                  Curl_pgrs_since_ms(data, pnow, TIMER_STARTOP);
    if(!timeleft_ms)
      timeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
  }

  if(!ctimeleft_ms)
    return timeleft_ms;
  else if(!timeleft_ms)
    return ctimeleft_ms;
  return CURLMIN(ctimeleft_ms, timeleft_ms);
}

/**
 * @brief Time left for the transfer/connection, using the current time.
 *
 * @param[in] data Transfer.
 * @return Same values as timeleft_now_ms(): 0 for no limit, negative if
 *         expired, else the milliseconds left.
 * @see Curl_timeleft_now_ms()
 */
timediff_t Curl_timeleft_ms(struct Curl_easy *data)
{
  return timeleft_now_ms(data, Curl_pgrs_now(data));
}

/**
 * @brief Time left for the transfer/connection at a given time.
 *
 * @param[in] data Transfer.
 * @param[in] pnow Time to compute with, avoids another clock query.
 * @return Same values as timeleft_now_ms(): 0 for no limit, negative if
 *         expired, else the milliseconds left.
 * @see Curl_timeleft_ms()
 */
timediff_t Curl_timeleft_now_ms(struct Curl_easy *data,
                                const struct curltime *pnow)
{
  return timeleft_now_ms(data, pnow);
}

/**
 * @brief Get the socket and connection of the most recent transfer.
 *
 * Works for an easy handle that has been used for curl_easy_perform(), or
 * that is associated with a multi handle and whose connection was detached
 * with CURLOPT_CONNECT_ONLY.
 *
 * @param[in]  data  Transfer.
 * @param[out] connp Receives the connection, or NULL if there is none. May
 *                   be NULL itself if the caller is not interested.
 * @return The first socket of the connection.
 * @return CURL_SOCKET_BAD in case of failure.
 * @warning The returned connection is owned by the connection pool and may
 *          be closed or reused at any time.
 */
curl_socket_t Curl_getconnectinfo(struct Curl_easy *data,
                                  struct connectdata **connp)
{
  /* this works for an easy handle:
   * - that has been used for curl_easy_perform()
   * - that is associated with a multi handle, and whose connection
   *   was detached with CURLOPT_CONNECT_ONLY
   */
  struct connectdata *conn = Curl_cpool_get_last_conn(data);
  if(connp)
    *connp = conn;
  return conn ? conn->sock[FIRSTSOCKET] : CURL_SOCKET_BAD;
}

/**
 * @brief Change whether the connection is kept or closed after use.
 *
 * @param[in,out] conn Connection to change, must not be NULL.
 * @param[in]     ctrl One of CONNCTRL_CONN_KEEP (clear the close flag),
 *                     CONNCTRL_CONN_CLOSE (set it) or CONNCTRL_STREAM_CLOSE
 *                     (close, but only if the connection is not
 *                     multiplexed, as a stream close then does not affect
 *                     the connection).
 * @note Any other value triggers an assertion in debug builds.
 */
void Curl_conncontrol(struct connectdata *conn, int ctrl)
{
  if(!conn) {
    DEBUGASSERT(0);
    return;
  }
  switch(ctrl) {
    case CONNCTRL_CONN_KEEP:
      conn->bits.close = FALSE;
      break;
    case CONNCTRL_CONN_CLOSE:
      conn->bits.close = TRUE;
      break;
    case CONNCTRL_STREAM_CLOSE:
      /* stream close when multiplexing does not affect connection */
      if(!Curl_conn_is_multiplex(conn, FIRSTSOCKET))
        conn->bits.close = TRUE;
      break;
    default:
      DEBUGASSERT(0);
      break;
  }
}

/**
 * @brief Set up the connection filter chain for a socket index.
 *
 * Installs HTTPS-specific filters for https, otherwise the default
 * setup filter, and adds a DNS resolve filter for the first peer so
 * resolving starts right away. Does not connect yet.
 *
 * @param[in,out] data      Transfer.
 * @param[in,out] conn      Connection to set up.
 * @param[in]     sockindex FIRSTSOCKET or SECONDARYSOCKET.
 * @param[in]     ssl_mode  CURL_CF_SSL_* mode for the filters.
 * @return CURLE_OK on success.
 * @return CURLE_FAILED_INIT if the connection has no first peer.
 * @return Any error from creating the filters, e.g. CURLE_OUT_OF_MEMORY.
 * @pre conn->scheme is set and no filter exists yet for sockindex.
 * @post On success conn->cfilter[sockindex] is not NULL.
 * @see Curl_conn_connect()
 */
CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int8_t sockindex,
                         int ssl_mode)
{
  struct Curl_peer *first_peer = Curl_conn_get_first_peer(conn, sockindex);
  CURLcode result = CURLE_OK;
  uint8_t dns_queries;

  DEBUGASSERT(data);
  DEBUGASSERT(conn->scheme);
  DEBUGASSERT(!conn->cfilter[sockindex]);

  if(!first_peer)
    return CURLE_FAILED_INIT;

#ifndef CURL_DISABLE_HTTP
  if(!conn->cfilter[sockindex] &&
     conn->scheme->protocol == CURLPROTO_HTTPS) {
    DEBUGASSERT(ssl_mode != CURL_CF_SSL_DISABLE);
    result = Curl_cf_https_setup(
      data, Curl_conn_get_destination(conn, sockindex), conn, sockindex);
    if(result)
      goto out;
  }
#endif /* !CURL_DISABLE_HTTP */

  /* Still no cfilter set, apply default. */
  if(!conn->cfilter[sockindex]) {
    result = Curl_cf_setup_add(data, conn, sockindex,
                               conn->transport_wanted, ssl_mode);
    if(result)
      goto out;
  }

  /* Whatever the filter chain will be in the end, it will need the
   * resolving of `first_peer`. Add that now so the resolve is started
   * right away. */
  dns_queries = Curl_resolv_dns_queries(data, conn->ip_version);
  result = Curl_conn_dns_add_addr_resolve(data, conn, sockindex,
                                          first_peer, dns_queries,
                                          conn->transport_wanted);
  if(result)
    goto out;

  DEBUGASSERT(conn->cfilter[sockindex]);
out:
  return result;
}

#ifdef CURLVERBOSE
/**
 * @brief Log the established connection (verbose builds only).
 * @internal
 *
 * @param[in] data Transfer.
 * @param[in] cf   Connected filter to query for address information.
 * @return CURLE_OK on success or if not verbose.
 * @return The error from querying the IP information.
 */
static CURLcode conn_connect_trace(struct Curl_easy *data,
                                   struct Curl_cfilter *cf)
{
  if(Curl_trc_is_verbose(data)) {
    struct ip_quadruple ipquad;
    bool is_ipv6;
    CURLcode result;

    result = Curl_conn_cf_get_ip_info(cf, data, &is_ipv6, &ipquad);
    if(result)
      return result;

    infof(data, "Established %sconnection to %s (%s port %u) from %s port %u ",
          (cf->sockindex == SECONDARYSOCKET) ? "2nd " : "",
          CURL_CONN_HOST_DISPNAME(data->conn),
          ipquad.remote_ip, ipquad.remote_port,
          ipquad.local_ip, ipquad.local_port);
  }
  return CURLE_OK;
}
#endif

/**
 * @brief Update connection statistics.
 * @internal
 *
 * Statistics are only gathered for the first socket, not the second.
 *
 * @param[in,out] data      Transfer.
 * @param[in]     sockindex Socket index the report is about.
 */
static void conn_report_stats(struct Curl_easy *data, int sockindex)
{
  /* We do gather stats for the second socket...yet */
  if(sockindex == FIRSTSOCKET) {
    Curl_conn_cntrl_report_stats(data, data->conn, sockindex);
  }
}

/**
 * @brief Report a failed connect attempt to the filters and statistics.
 *
 * Only filters connected at the IP level have information to update.
 * Filters still racing for a connection, such as happy eyeballing, pass
 * the request on to a connected one only.
 *
 * @param[in,out] data      Transfer.
 * @param[in]     sockindex Socket index; only FIRSTSOCKET is acted upon.
 */
void Curl_conn_report_failed(struct Curl_easy *data, int8_t sockindex)
{
  if(!data->conn || (sockindex != FIRSTSOCKET))
    return;
  /* Only filters connected at IP level have info to update. Filters
   * still racing for a connection, like happy eyeballing, pass it on
   * to a connected one only. */
  (void)Curl_conn_cf_cntrl(data->conn->cfilter[sockindex], data, TRUE,
                           CF_CTRL_CONN_INFO_UPDATE, 0, NULL);
  conn_report_stats(data, sockindex);
}

/**
 * @brief Drive the connection filter chain towards "connected".
 *
 * Calls the filter's do_connect() until it reports done. In blocking mode
 * it polls the socket (in slices of at most one second) and honors the
 * remaining timeout. In non-blocking mode it returns after one attempt.
 * On success the setup filters are removed and connection info and
 * statistics are stored at the connection.
 *
 * @param[in,out] data      Transfer with data->conn set.
 * @param[in]     sockindex FIRSTSOCKET or SECONDARYSOCKET.
 * @param[in]     blocking  TRUE to wait until connected or failed.
 * @param[out]    done      TRUE if the connection is fully established.
 * @return CURLE_OK on success, check done to see if connecting finished.
 * @return CURLE_BAD_FUNCTION_ARGUMENT for an invalid sockindex.
 * @return CURLE_FAILED_INIT if no filter chain exists or a transfer that
 *         requires SSL is not connected via SSL.
 * @return CURLE_OPERATION_TIMEDOUT if the connect timeout expired.
 * @return CURLE_COULDNT_CONNECT if polling failed.
 * @return Any other error returned by a filter.
 * @note Protocols without network (PROTOPT_NONETWORK) return done at once.
 * @see Curl_conn_setup()
 */
CURLcode Curl_conn_connect(struct Curl_easy *data,
                           int8_t sockindex,
                           bool blocking,
                           bool *done)
{
/**
 * @brief Number of poll entries kept on the stack while connecting.
 * @internal
 */
#define CF_CONN_NUM_POLLS_ON_STACK 5
  struct pollfd a_few_on_stack[CF_CONN_NUM_POLLS_ON_STACK];
  struct easy_pollset ps;
  struct curl_pollfds cpfds;
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(data->conn->scheme->flags & PROTOPT_NONETWORK) {
    *done = TRUE;
    return CURLE_OK;
  }

  cf = data->conn->cfilter[sockindex];
  if(!cf) {
    *done = FALSE;
    return CURLE_FAILED_INIT;
  }

  *done = (bool)cf->connected;
  if(*done)
    return CURLE_OK;

  if(data->conn->connect_start_ms < 0) {
    data->conn->connect_start_ms =
      curlx_ptimediff_ms(Curl_pgrs_now(data), &data->conn->created);
  }

  Curl_pollset_init(&ps);
  Curl_pollfds_init(&cpfds, a_few_on_stack, CF_CONN_NUM_POLLS_ON_STACK);
  while(!*done) {
    if(Curl_conn_needs_flush(data, sockindex)) {
      DEBUGF(infof(data, "Curl_conn_connect(index=%d), flush", sockindex));
      result = Curl_conn_flush(data, sockindex);
      if(result && (result != CURLE_AGAIN))
        goto out;
    }

    result = cf->cft->do_connect(cf, data, done);
    CURL_TRC_CF(data, cf, "Curl_conn_connect(block=%d) -> %d, done=%d",
                blocking, (int)result, *done);
    if(!result && *done) {
      /* A final sanity check on connection security */
      if((data->state.origin->scheme->flags & PROTOPT_SSL) &&
         (sockindex == FIRSTSOCKET) &&
         !Curl_conn_is_ssl(data->conn, FIRSTSOCKET)) {
        DEBUGASSERT(0);
        failf(data, "transfer requires SSL, but not connected via SSL");
        result = CURLE_FAILED_INIT;
        goto out;
      }
      /* Now that the complete filter chain is connected, let all filters
       * persist information at the connection. E.g. cf-socket sets the
       * socket and ip related information. */
      Curl_conn_cntrl_update_info(data, data->conn);
      conn_report_stats(data, sockindex);
      Curl_cpool_conn_was_used(data, data->conn, Curl_pgrs_now(data));
      VERBOSE(result = conn_connect_trace(data, cf));
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "connected"));
      Curl_conn_remove_setup_filters(data, sockindex);
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "reduced to"));
      data->conn->connect_start_ms = -1;
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "Curl_conn_connect(), filter returned %d",
                  (int)result);
      VERBOSE(Curl_conn_trc_filters(data, sockindex, "failed to connect"));
      Curl_conn_report_failed(data, sockindex);
      goto out;
    }

    if(!blocking)
      goto out;
    else {
      /* check allowed time left */
      const struct curltime *pnow = Curl_pgrs_now(data);
      timediff_t timeout_ms = Curl_timeleft_now_ms(data, pnow);
      curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
      int rc;

      if(timeout_ms < 0) {
        /* no need to continue if time already is up */
        failf(data, "connect timeout");
        result = CURLE_OPERATION_TIMEDOUT;
        goto out;
      }

      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), do poll");
      Curl_pollset_reset(&ps);
      Curl_pollfds_reset(&cpfds);
      /* In general, we want to send after connect, wait on that. */
      if(sockfd != CURL_SOCKET_BAD)
        result = Curl_pollset_set_out_only(data, &ps, sockfd);
      if(!result)
        result = Curl_conn_adjust_pollset(data, data->conn, &ps);
      if(result)
        goto out;
      result = Curl_pollfds_add_ps(&cpfds, &ps);
      if(result)
        goto out;

      rc = Curl_poll(cpfds.pfds, cpfds.n,
                     CURLMIN(timeout_ms ? timeout_ms : 1000,
                             (cpfds.n ? 1000 : 10)));
      CURL_TRC_CF(data, cf, "Curl_conn_connect(block=1), Curl_poll() -> %d",
                  rc);
      if(rc < 0) {
        result = CURLE_COULDNT_CONNECT;
        goto out;
      }
      /* continue iterating */
    }
  }

out:
  Curl_pollset_cleanup(&ps);
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

/**
 * @brief Mark the connection as multiplexed.
 *
 * When the flag changes and the connection is attached to a multi handle,
 * the multi handle is notified so waiting transfers can be reconsidered.
 *
 * @param[in,out] conn Connection to mark.
 */
void Curl_conn_set_multiplex(struct connectdata *conn)
{
  if(!conn->bits.multiplex) {
    conn->bits.multiplex = TRUE;
    if(conn->attached_multi) {
      Curl_multi_connchanged(conn->attached_multi);
    }
  }
}

/**
 * @brief Get the origin peer for a socket index.
 *
 * @param[in] conn      Connection.
 * @param[in] sockindex FIRSTSOCKET or SECONDARYSOCKET.
 * @return The origin peer of that socket.
 * @note The returned pointer is owned by the connection.
 */
struct Curl_peer *Curl_conn_get_origin(struct connectdata *conn,
                                       int8_t sockindex)
{
  return (sockindex == SECONDARYSOCKET) ?
    conn->origin2 : conn->origin;
}

/**
 * @brief Get the peer to connect to for a socket index.
 *
 * This is the "via" peer if one is set (e.g. from CURLOPT_CONNECT_TO),
 * otherwise the origin.
 *
 * @param[in] conn      Connection.
 * @param[in] sockindex FIRSTSOCKET or SECONDARYSOCKET.
 * @return The destination peer, owned by the connection.
 */
struct Curl_peer *Curl_conn_get_destination(struct connectdata *conn,
                                            int8_t sockindex)
{
  return (sockindex == SECONDARYSOCKET) ?
    (conn->via_peer2 ? conn->via_peer2 : conn->origin2) :
    (conn->via_peer ? conn->via_peer : conn->origin);
}

/**
 * @brief Get the first peer the connection must talk to.
 *
 * With a SOCKS or HTTP proxy this is the proxy peer, otherwise the same
 * as Curl_conn_get_destination().
 *
 * @param[in] conn      Connection.
 * @param[in] sockindex FIRSTSOCKET or SECONDARYSOCKET.
 * @return The first peer, owned by the connection, or NULL if not set.
 */
struct Curl_peer *Curl_conn_get_first_peer(struct connectdata *conn,
                                           int8_t sockindex)
{
#ifndef CURL_DISABLE_PROXY
  if(conn->socks_proxy.peer)
    return conn->socks_proxy.peer;
  if(conn->http_proxy.peer)
    return conn->http_proxy.peer;
#endif
  return (sockindex == SECONDARYSOCKET) ?
    (conn->via_peer2 ? conn->via_peer2 : conn->origin2) :
    (conn->via_peer ? conn->via_peer : conn->origin);
}
