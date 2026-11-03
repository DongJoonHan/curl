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
 * @file transfer.c
 * @brief Generic transfer engine: receive/send loop and request setup.
 *
 * Contains the protocol independent parts of performing a transfer: the
 * non-blocking receive and send handlers driven by the multi interface
 * (Curl_sendrecv()), the preparation done right before a transfer starts
 * (Curl_pretransfer()), connection retry logic, and the small Curl_xfer_*
 * helpers that protocol handlers use to set up directions, write response
 * data to the client, send and receive on the connection and pause or
 * unpause either direction.
 *
 * All functions operate on a struct Curl_easy and are not thread-safe for
 * the same handle; a handle must be driven by a single thread at a time.
 *
 * @defgroup xfer Transfer engine
 * @brief Internal helpers that drive a single transfer.
 * @internal
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
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifndef HAVE_SOCKET
#error "We cannot compile without socket() support"
#endif

#include "urldata.h"

#include "cfilters.h"
#include "cw-out.h"
#include "transfer.h"
#include "sendf.h"
#include "curl_trc.h"
#include "progress.h"
#include "http.h"
#include "url.h"
#include "getinfo.h"
#include "multiif.h"
#include "connect.h"
#include "hsts.h"
#include "setopt.h"
#include "headers.h"
#include "bufref.h"
#include "rtsp.h"

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_SMTP) || \
  !defined(CURL_DISABLE_IMAP)
/**
 * @brief Find a custom header in the user supplied header list.
 *
 * Checks the linked list of custom headers (CURLOPT_HTTPHEADER) for a
 * particular header name prefix. The comparison is case-insensitive and
 * the character following the prefix must be a header separator.
 *
 * @param[in] data        Easy handle holding the custom header list.
 * @param[in] thisheader  Header name prefix, WITHOUT the trailing colon.
 * @param[in] thislen     Length of @p thisheader, must be non-zero.
 * @return Pointer to the data of the first matching header, or NULL if none
 *         matched.
 *
 * @note The returned string is owned by the slist in @p data and must not
 *       be freed or modified.
 * @warning The pointer is only valid until the header list is changed.
 */
char *Curl_checkheaders(const struct Curl_easy *data,
                        const char *thisheader,
                        const size_t thislen)
{
  struct curl_slist *head;
  DEBUGASSERT(thislen);
  DEBUGASSERT(thisheader[thislen - 1] != ':');

  for(head = data->set.headers; head; head = head->next) {
    if(curl_strnequal(head->data, thisheader, thislen) &&
       Curl_headersep(head->data[thislen]))
      return head->data;
  }

  return NULL;
}
#endif

/**
 * @brief Tell if more data may be readable without waiting for the socket.
 *
 * For FTP the secondary (data) connection is queried. For SCP and SFTP
 * (libssh2) we can never be sure its internal buffers are drained, so we
 * must always try until EAGAIN comes back.
 *
 * @param[in] data         Easy handle with an attached connection.
 * @param[in] rcvd_eagain  TRUE if the last receive returned CURLE_AGAIN.
 * @return Non-zero if there may be pending data, 0 otherwise.
 * @pre data->conn is set.
 * @internal
 */
static int data_pending(struct Curl_easy *data, bool rcvd_eagain)
{
  struct connectdata *conn = data->conn;

  if(conn->scheme->protocol & PROTO_FAMILY_FTP)
    return Curl_conn_data_pending(data, SECONDARYSOCKET);

  /* in the case of libssh2, we can never be really sure that we have emptied
     its internal buffers so we MUST always try until we get EAGAIN back */
  return (!rcvd_eagain &&
          conn->scheme->protocol & (CURLPROTO_SCP | CURLPROTO_SFTP)) ||
         Curl_conn_data_pending(data, FIRSTSOCKET);
}

/**
 * @brief Check CURLOPT_TIMECONDITION against the remote document time.
 *
 * Compares the modification time of the remote document with the time
 * given by CURLOPT_TIMEVALUE, honoring if-modified-since and
 * if-unmodified-since semantics. If a condition is not met, the info
 * flag data->info.timecond is set.
 *
 * @param[in,out] data       Easy handle.
 * @param[in]     timeofdoc  Remote document time, 0 if unknown.
 * @return TRUE if the transfer should proceed (condition met, no condition
 *         set or document time unknown).
 * @return FALSE if the condition was not met.
 */
bool Curl_meets_timecondition(struct Curl_easy *data, time_t timeofdoc)
{
  if((timeofdoc == 0) || (data->set.timevalue == 0))
    return TRUE;

  switch(data->set.timecondition) {
  case CURL_TIMECOND_IFMODSINCE:
  default:
    if(timeofdoc <= data->set.timevalue) {
      infof(data, "The requested document is not new enough");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    if(timeofdoc >= data->set.timevalue) {
      infof(data, "The requested document is not old enough");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  }

  return TRUE;
}

/**
 * @brief Try once to shut down the receiving side of the connection.
 *
 * @param[in,out] data  Easy handle, may be NULL.
 * @param[out]    done  Set to TRUE when the shutdown has completed.
 * @return CURLE_OK on progress or completion, CURLE_FAILED_INIT if there
 *         is no handle or connection, or the error from the connection
 *         shutdown attempt.
 * @internal
 */
static CURLcode xfer_recv_shutdown(struct Curl_easy *data, bool *done)
{
  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  return Curl_cshutdn_try_once_idx(data, data->conn->recv_idx, done);
}

/**
 * @brief Tell if the receive side of the connection is already shutting
 *        down.
 *
 * @param[in] data  Easy handle, may be NULL.
 * @return TRUE if the shutdown of the receive filter chain has started,
 *         FALSE otherwise (also without a connection).
 * @internal
 */
static bool xfer_recv_shutdown_started(struct Curl_easy *data)
{
  if(!data || !data->conn)
    return FALSE;
  return CURL_CONN_IN_SHUTDOWN(data->conn, data->conn->recv_idx);
}

/**
 * @brief Try once to shut down the sending side of the connection.
 *
 * @param[in,out] data  Easy handle, may be NULL.
 * @param[out]    done  Set to TRUE when the shutdown has completed.
 * @return CURLE_OK on progress or completion, CURLE_FAILED_INIT if there
 *         is no handle or connection, or the error from the shutdown.
 * @see Curl_xfer_set_shutdown()
 */
CURLcode Curl_xfer_send_shutdown(struct Curl_easy *data, bool *done)
{
  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  return Curl_cshutdn_try_once_idx(data, data->conn->send_idx, done);
}

/**
 * @brief Receive raw response data for the transfer.
 *
 * When reading BODY data on a connection that cannot reliably signal EOS
 * and the body size is known, the read size is limited to what is still
 * expected. Once a receive shutdown has started, nothing more is read.
 * A zero length read on a transfer marked for shutdown continues the
 * shutdown and reports CURLE_AGAIN until it completes.
 *
 * @param[in,out] data          The transfer.
 * @param[out]    buf           Buffer to keep the response data received.
 * @param[in]     blen          Length of @p buf, must be non-zero.
 * @param[in]     eos_reliable  TRUE if EOS detection in the underlying
 *                              connection is reliable.
 * @param[out]    pnread        Number of bytes placed in @p buf, 0 at EOS.
 * @return CURLE_OK on success (including EOS with *pnread == 0).
 * @return CURLE_AGAIN if no data is available or the shutdown is pending.
 * @return Any other CURLcode on a receive or shutdown error.
 * @internal
 */
static CURLcode xfer_recv_resp(struct Curl_easy *data,
                               char *buf, size_t blen,
                               bool eos_reliable,
                               size_t *pnread)
{
  CURLcode result;

  DEBUGASSERT(blen > 0);
  *pnread = 0;
  /* If we are reading BODY data and the connection does NOT handle EOF
   * and we know the size of the BODY data, limit the read amount */
  if(!eos_reliable && !data->req.header && data->req.size != -1) {
    blen = curlx_sotouz_range(data->req.size - data->req.bytecount, 0, blen);
  }
  else if(xfer_recv_shutdown_started(data)) {
    /* we already received everything. Do not try more. */
    blen = 0;
  }

  if(blen) {
    result = Curl_xfer_recv(data, buf, blen, pnread);
    if(result)
      return result;
  }

  if(*pnread == 0) {
    if(data->req.shutdown) {
      bool done;
      result = xfer_recv_shutdown(data, &done);
      if(result)
        return result;
      if(!done) {
        return CURLE_AGAIN;
      }
    }
    DEBUGF(infof(data, "sendrecv_dl: we are done"));
  }
  return CURLE_OK;
}

/**
 * @brief Read response data when the connection is readable.
 *
 * Loops up to a bounded number of times, reading into the shared transfer
 * buffer and handing the data to Curl_xfer_write_resp(). Honors download
 * rate limits, stops when the response is complete and, when it did not
 * drain the connection, marks the transfer dirty so it is run again
 * without waiting for a socket event. Also aborts a still running upload
 * when the connection must close after the download is finished.
 *
 * @param[in,out] data  The transfer.
 * @param[in,out] k     The request state of @p data (data->req).
 * @return CURLE_OK when no error occurred (more data may remain).
 * @return Any CURLcode from receiving, writing to the client or stopping
 *         the request; CURLE_AGAIN from the receive is not an error.
 * @note The transfer buffer is borrowed from the multi handle and is always
 *       released again before returning.
 * @internal
 */
static CURLcode sendrecv_dl(struct Curl_easy *data,
                            struct SingleRequest *k)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  char *buf, *xfer_buf;
  size_t blen, xfer_blen;
  int maxloops = 10;
  bool is_multiplex = FALSE;
  bool rcvd_eagain = FALSE;
  bool is_eos = FALSE, rate_limited = FALSE;

  result = Curl_multi_xfer_buf_borrow(data, &xfer_buf, &xfer_blen);
  if(result)
    goto out;

  /* This is where we loop until we have read everything there is to
     read or we get a CURLE_AGAIN */
  do {
    size_t bytestoread;

    if(!is_multiplex) {
      /* Multiplexed connection have inherent handling of EOF and we do not
       * have to carefully restrict the amount we try to read.
       * Multiplexed changes only in one direction. */
      is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);
    }

    buf = xfer_buf;
    bytestoread = xfer_blen;

    if(bytestoread && Curl_rlimit_active(&data->progress.dl.rlimit)) {
      curl_off_t dl_avail = Curl_rlimit_avail(&data->progress.dl.rlimit, NULL);
#if 0
      DEBUGF(infof(data, "dl_rlimit, available=%" FMT_OFF_T, dl_avail));
#endif
      /* In case of rate limited downloads: if this loop already got data and
       * less than 16k is left in the limit, break out. We want to stutter a
       * bit to keep in the limit, but too small receives will cost cpu
       * unnecessarily. */
      if(dl_avail <= 0) {
        rate_limited = TRUE;
        break;
      }
      if(dl_avail < (curl_off_t)bytestoread)
        bytestoread = (size_t)dl_avail;
    }

    rcvd_eagain = FALSE;
    result = xfer_recv_resp(data, buf, bytestoread, is_multiplex, &blen);
    if(result) {
      if(result != CURLE_AGAIN)
        goto out; /* real error */
      rcvd_eagain = TRUE;
      result = CURLE_OK;
      if(data->req.download_done && data->req.no_body &&
         !data->req.resp_trailer) {
        DEBUGF(infof(data, "EAGAIN, download done, no trailer announced, "
                     "not waiting for EOS"));
        blen = 0;
        /* continue as if we received the EOS */
      }
      else
        break; /* get out of loop */
    }

    /* We only get a 0-length receive at the end of the response */
    is_eos = (blen == 0);

    if(!blen) {
      result = Curl_req_stop_send_recv(data);
      if(result)
        goto out;
      if(k->eos_written) /* already did write this to client, leave */
        break;
    }

    result = Curl_xfer_write_resp(data, buf, blen, is_eos);
    if(result || data->req.done)
      goto out;

    /* if we are done, we stop receiving. On multiplexed connections,
     * we should read the EOS. Which may arrive as meta data after
     * the bytes. Not taking it in might lead to RST of streams. */
    if((!is_multiplex && data->req.download_done) || is_eos) {
      CURL_REQ_CLEAR_RECV(data);
    }
    /* if we stopped receiving, leave the loop */
    if(!CURL_REQ_WANT_RECV(data))
      break;

  } while(maxloops--);

  if(!is_eos && !rate_limited && CURL_REQ_WANT_RECV(data) &&
     (!rcvd_eagain || data_pending(data, rcvd_eagain))) {
    /* Did not read until EAGAIN/EOS or there is still data pending
     * in buffers. Mark as read-again via simulated SELECT results. */
    Curl_multi_mark_dirty(data);
    CURL_TRC_M(data, "sendrecv_dl() no EAGAIN/pending data, mark as dirty");
  }

  if(!CURL_REQ_WANT_RECV(data) && CURL_REQ_WANT_SEND(data) &&
     (conn->bits.close || is_multiplex)) {
    /* When we have read the entire thing and the close bit is set, the server
       may now close the connection. If there is now any kind of sending going
       on from our side, we need to stop that immediately. */
    infof(data, "we are done reading and this is set to close, stop send");
    Curl_req_abort_sending(data);
  }

out:
  Curl_multi_xfer_buf_release(data, xfer_buf);
  if(result)
    DEBUGF(infof(data, "sendrecv_dl() -> %d", (int)result));
  return result;
}

/**
 * @brief Send upload data when the socket is writable.
 *
 * @param[in,out] data  The transfer.
 * @return CURLE_OK if there is nothing (more) to send or the send worked,
 *         otherwise the CURLcode from Curl_req_send_more().
 * @pre Sending is not yet done for the request.
 * @internal
 */
static CURLcode sendrecv_ul(struct Curl_easy *data)
{
  /* We should not get here when the sending is already done. */
  DEBUGASSERT(!Curl_req_done_sending(data));

  if(!Curl_req_done_sending(data))
    return Curl_req_send_more(data);
  return CURLE_OK;
}

/**
 * @brief Low-level function to read and write data to/from the connection.
 *
 * Called by the multi state machine while a transfer is in the performing
 * state. It receives and/or sends data as wanted by the request, then
 * checks the overall timeout, whether a known-size response was
 * truncated, marks the request done when no I/O is wanted anymore, and
 * finally updates progress and runs the low speed check.
 *
 * @param[in,out] data  The transfer.
 * @return CURLE_OK on success, also if the transfer is blocked (paused).
 * @return CURLE_OPERATION_TIMEDOUT when the transfer timeout is exceeded.
 * @return CURLE_PARTIAL_FILE when the connection closed before all the
 *         announced bytes arrived (and no redirect is pending).
 * @return Other CURLcode values from reading, writing or the progress
 *         callback (for instance CURLE_ABORTED_BY_CALLBACK).
 * @post data->req.done is TRUE if no more I/O is wanted.
 */
CURLcode Curl_sendrecv(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  const struct curltime *pnow = NULL;
  CURLcode result = CURLE_OK;

  if(Curl_xfer_is_blocked(data)) {
    result = CURLE_OK;
    goto out;
  }

  /* We go ahead and do a read if we have a readable socket or if the stream
     was rewound (in which case we have data in a buffer) */
  if(CURL_REQ_WANT_RECV(data)) {
    result = sendrecv_dl(data, k);
    if(result || data->req.done)
      goto out;
  }

  /* If we still have writing to do, we check if we have a writable socket. */
  if(Curl_req_want_send(data)) {
    result = sendrecv_ul(data);
    if(result)
      goto out;
  }

  pnow = Curl_pgrs_now(data);
  if(CURL_REQ_WANT_IO(data)) {
    if(Curl_timeleft_now_ms(data, pnow) < 0) {
      if(k->size != -1) {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " out of %"
              FMT_OFF_T " bytes received",
              Curl_pgrs_since_ms(data, NULL, TIMER_STARTSINGLE),
              k->bytecount, k->size);
      }
      else {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " bytes received",
              Curl_pgrs_since_ms(data, NULL, TIMER_STARTSINGLE),
              k->bytecount);
      }
      result = CURLE_OPERATION_TIMEDOUT;
      goto out;
    }
  }
  else {
    /*
     * The transfer has been performed. Make some general checks before
     * returning.
     */
    if(!data->req.no_body && (k->size != -1) &&
       (k->bytecount != k->size) && !k->newurl) {
      failf(data, "transfer closed with %" FMT_OFF_T
            " bytes remaining to read", k->size - k->bytecount);
      result = CURLE_PARTIAL_FILE;
      goto out;
    }
  }

  /* If there is nothing more to send/recv, the request is done */
  if(!CURL_REQ_WANT_IO(data))
    data->req.done = TRUE;

  result = Curl_pgrsCheckX(data, pnow);

out:
  if(result)
    DEBUGF(infof(data, "Curl_sendrecv() -> %d", (int)result));
  return result;
}

/**
 * @brief Reset read-callback and upload state when entering CONNECT.
 *
 * Gets called each time the handle switches to CONNECT, which means once
 * for each subsequent redirect and so on.
 *
 * @param[in,out] data  The transfer.
 */
void Curl_init_CONNECT(struct Curl_easy *data)
{
  data->state.fread_func = data->set.fread_func_set;
  data->state.in = data->set.in_set;
  data->state.upload = (data->state.httpreq == HTTPREQ_PUT);
}

/**
 * @brief Prepare a handle immediately before a transfer starts.
 *
 * Called once per transfer, no matter if it has redirects or does
 * multi-pass authentication. It resets per-transfer state, validates that a
 * URL is set (taking CURLOPT_CURLU into account), computes the upload size,
 * loads cookie, resolve and HSTS data, ignores SIGPIPE where needed,
 * resets progress, prepares FTP wildcard matching and clears client
 * readers/writers and collected headers.
 *
 * @param[in,out] data  The transfer.
 * @return CURLE_OK on success.
 * @return CURLE_URL_MALFORMAT if no URL is set or the CURLU handle cannot
 *         produce one.
 * @return CURLE_BAD_FUNCTION_ARGUMENT if POSTFIELDS is mixed with
 *         RESUME_FROM.
 * @return CURLE_OUT_OF_MEMORY on allocation failure.
 * @return Other CURLcode values from loading cookies, hosts pairs or HSTS.
 *
 * @warning With CURLOPT_CURLU the URL is copied from the CURLU handle at
 *          this point; later changes to that handle are not seen until
 *          the next transfer.
 */
CURLcode Curl_pretransfer(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;

  /* Reset the retry count at the start of each request.
   * If the retry count is not reset, when the connection drops,
   * it will not enter the retry mechanism on CONN_MAX_RETRIES + 1 attempts
   * and will immediately throw
   * "Connection died, tried CONN_MAX_RETRIES times before giving up".
   * By resetting it here, we ensure each new request starts fresh. */
  data->state.retrycount = 0;

  if(!CURL_EASY_STR(data, STRING_SET_URL) && !data->set.uh) {
    /* we cannot do anything without URL */
    failf(data, "No URL set");
    return CURLE_URL_MALFORMAT;
  }

  /* CURLOPT_CURLU overrides CURLOPT_URL and the contents of the CURLU handle
     is allowed to be changed by the user between transfers */
  if(data->set.uh) {
    char *url = NULL;
    CURLUcode uc;
    uc = curl_url_get(data->set.uh, CURLUPART_URL, &url, 0);
    if(uc) {
      /* clear the pointer to not point to freed memory anymore */
      Curl_bufref_set(&data->state.url, NULL, 0, NULL);
      failf(data, "No URL set");
      return CURLE_URL_MALFORMAT;
    }
    result = CURL_EASY_STR_SETN(data, STRING_SET_URL, url);
    if(result)
      return result;
  }

  Curl_bufref_set(&data->state.url, CURL_EASY_STR(data, STRING_SET_URL),
                  0, NULL);

  if(data->set.postfields && data->set.set_resume_from) {
    /* we cannot */
    failf(data, "cannot mix POSTFIELDS with RESUME_FROM");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  data->state.prefer_ascii = data->set.prefer_ascii;
#ifdef CURL_LIST_ONLY_PROTOCOL
  data->state.list_only = data->set.list_only;
#endif
  data->state.httpreq = data->set.method;

  /* initial transfer request coming up, forget the initial origin
   * from a previous perform() on this handle. */
  Curl_peer_unlink(&data->state.initial_origin);
  Curl_peer_unlink(&data->state.origin);
  data->state.requests = 0;
  data->state.followlocation = 0; /* reset the location-follow counter */
  data->state.this_is_a_follow = FALSE; /* reset this */
  data->state.http_ignorecustom = FALSE; /* use custom HTTP method */
  data->state.errorbuf = FALSE; /* no error has occurred */
#ifndef CURL_DISABLE_HTTP
  Curl_http_neg_init(data, &data->state.http_neg);
#endif
  data->state.authproblem = FALSE;
  data->state.authhost.want = data->set.httpauth;
  data->state.authproxy.want = data->set.proxyauth;
  curlx_safefree(data->info.wouldredirect);
  curlx_safefree(data->info.effective_url);
  Curl_data_priority_clear_state(data);
  if(data->set.http_auto_referer)
    Curl_bufref_free(&data->state.referer);
  if(CURL_EASY_STR(data, STRING_SET_REFERER))
    Curl_bufref_set(&data->state.referer,
                    CURL_EASY_STR(data, STRING_SET_REFERER), 0, NULL);
  else
    Curl_bufref_free(&data->state.referer);

  if(data->state.httpreq == HTTPREQ_PUT)
    data->state.infilesize = data->set.filesize;
  else if((data->state.httpreq != HTTPREQ_GET) &&
          (data->state.httpreq != HTTPREQ_HEAD)) {
    data->state.infilesize = data->set.postfieldsize;
    if(data->set.postfields && (data->state.infilesize == -1))
      data->state.infilesize = (curl_off_t)strlen(data->set.postfields);
  }
  else
    data->state.infilesize = 0;

  /* If there is a list of cookie files to read, do it now! */
  result = Curl_cookie_loadfiles(data,
                                 data->set.cookiesession ?
                                 COOKIE_NOSESSION : 0);
  if(!result)
    Curl_cookie_run(data); /* activate */

  /* If there is a list of host pairs to deal with */
  if(!result && data->state.resolve)
    result = Curl_loadhostpairs(data);

  if(!result)
    /* If there is a list of hsts files to read */
    result = Curl_hsts_loadfiles(data);

  if(!result) {
    /* Allow data->set.use_port to set which port to use. This needs to be
     * disabled for example when we follow Location: headers to URLs using
     * different ports! */
    data->state.allow_port = TRUE;

#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(MSG_NOSIGNAL)
    /*************************************************************
     * Tell signal handler to ignore SIGPIPE
     *************************************************************/
    if(!data->set.no_signal)
      data->state.prev_signal = signal(SIGPIPE, SIG_IGN);
#endif

    Curl_initinfo(data); /* reset session-specific information "variables" */
    Curl_pgrsResetTransferSizes(data);
    Curl_pgrsStart(data, NULL);

    /* In case the handle is reused and an authentication method was picked
       in the session we need to make sure we only use the one(s) we now
       consider to be fine */
    data->state.authhost.picked &= data->state.authhost.want;
    data->state.authproxy.picked &= data->state.authproxy.want;

#ifndef CURL_DISABLE_FTP
    data->state.wildcardmatch = data->set.wildcard_enabled;
#ifdef DEBUGBUILD
  if(getenv("CURL_DBG_FTP_WILDCARD"))
    data->state.wildcardmatch = TRUE;
#endif
    if(data->state.wildcardmatch) {
      struct WildcardData *wc;
      if(!data->wildcard) {
        data->wildcard = curlx_calloc(1, sizeof(struct WildcardData));
        if(!data->wildcard)
          return CURLE_OUT_OF_MEMORY;
      }
      wc = data->wildcard;
      if(wc->state < CURLWC_INIT) {
        if(wc->ftpwc)
          wc->dtor(wc->ftpwc);
        curlx_safefree(wc->pattern);
        curlx_safefree(wc->path);
        Curl_wildcard_init(wc); /* init wildcard structures */
      }
    }
#endif
    result = Curl_hsts_loadcb(data, data->hsts);
  }

  data->req.headerbytecount = 0;
  /* a previous transfer on this handle may have ended with a rewind request
   * still pending (a follow or auth retry that failed). This is a new
   * transfer, so drop those readers now instead of letting a later upload
   * read from them. */
  data->req.rewind_read = FALSE;
  Curl_client_reset(data);
  Curl_headers_cleanup(data);
  return result;
}

/**
 * @brief Decide if the request must be retried on a fresh connection.
 *
 * This happens when a reused connection turns out to be dead (no data was
 * exchanged) or when the server refused the stream. On retry the
 * connection is closed and the request rewound. At most CONN_MAX_RETRIES
 * attempts are made.
 *
 * @param[in,out] data  The transfer.
 * @param[out]    url   Set to a newly allocated copy of the URL when a
 *                      retry is wanted, otherwise NULL.
 * @return CURLE_OK, also if no retry is wanted; check @p url to tell.
 * @return CURLE_SEND_ERROR if the retry limit was exceeded.
 * @return CURLE_OUT_OF_MEMORY if the URL could not be duplicated.
 *
 * @note The returned URL is allocated with curlx_malloc() and the caller
 *       owns it and must release it.
 * @warning Uploads over non-HTTP/RTSP protocols are never retried since the
 *          request body cannot be assumed to be replayable.
 */
CURLcode Curl_retry_request(struct Curl_easy *data, char **url)
{
  struct connectdata *conn = data->conn;
  bool retry = FALSE;
  *url = NULL;

  /* if we are talking upload, we cannot do the checks below, unless the
     protocol is HTTP as when uploading over HTTP we will still get a
     response */
  if(data->state.upload &&
     !(conn->scheme->protocol & (PROTO_FAMILY_HTTP | CURLPROTO_RTSP)))
    return CURLE_OK;

  if(conn->bits.reuse &&
     (data->req.bytecount + data->req.headerbytecount == 0) &&
     ((!data->req.no_body && !data->req.done) ||
      (conn->scheme->protocol & PROTO_FAMILY_HTTP))
#ifndef CURL_DISABLE_RTSP
     && (data->set.rtspreq != RTSPREQ_RECEIVE)
#endif
    )
    /* We got no data, we attempted to reuse a connection. For HTTP this
       can be a retry so we try again regardless if we expected a body.
       For other protocols we only try again only if we expected a body.

       This might happen if the connection was left alive when we were
       done using it before, but that was closed when we wanted to read from
       it again. Bad luck. Retry the same request on a fresh connect! */
    retry = TRUE;
  else if(data->state.refused_stream &&
          (data->req.bytecount + data->req.headerbytecount == 0)) {
    /* This was sent on a refused stream, safe to rerun. A refused stream
       error can typically only happen on HTTP/2 level if the stream is safe
       to issue again, but the nghttp2 API can deliver the message to other
       streams as well, which is why this adds the check the data counters
       too. */
    infof(data, "REFUSED_STREAM, retrying a fresh connect");
    data->state.refused_stream = FALSE; /* clear again */
    retry = TRUE;
  }
  if(retry) {
/** Maximum number of fresh-connection retries for one request. */
#define CONN_MAX_RETRIES 5
    if(data->state.retrycount++ >= CONN_MAX_RETRIES) {
      failf(data, "Connection died, tried %d times before giving up",
            CONN_MAX_RETRIES);
      data->state.retrycount = 0;
      return CURLE_SEND_ERROR;
    }
    infof(data, "Connection died, retrying a fresh connect (retry count: %d)",
          data->state.retrycount);
    *url = Curl_bufref_dup(&data->state.url);
    if(!*url)
      return CURLE_OUT_OF_MEMORY;

    connclose(conn); /* close this connection */
    conn->bits.retry = TRUE; /* mark this as a connection we are about to
                                retry. Marking it this way should prevent i.e
                                HTTP transfers to return error because nothing
                                has been transferred! */
    Curl_creader_set_rewind(data, TRUE);
  }
  return CURLE_OK;
}

/**
 * @brief Configure the transfer directions and expected receive size.
 *
 * Stores the socket indexes to send and receive on in the connection,
 * initializes the request, sets the download size for progress when the
 * protocol does not parse headers, and enables the send/receive wanted
 * flags on the request.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     send_idx   Socket index to send on, or -1 for none.
 * @param[in]     recv_idx   Socket index to receive on, or -1 for none.
 * @param[in]     recv_size  How much to receive, -1 if unknown. Must be -1
 *                           when not receiving.
 * @pre data->conn is set and the indexes are in the range -1 to 1.
 * @internal
 */
static void xfer_setup(
  struct Curl_easy *data,   /* transfer */
  int8_t send_idx,             /* sockindex to send on or -1 */
  int8_t recv_idx,             /* sockindex to receive on or -1 */
  curl_off_t recv_size      /* how much to receive, -1 if unknown */
  )
{
  struct SingleRequest *k = &data->req;
  struct connectdata *conn = data->conn;

  DEBUGASSERT(conn);
  /* indexes are in range */
  DEBUGASSERT((send_idx <= 1) && (send_idx >= -1));
  DEBUGASSERT((recv_idx <= 1) && (recv_idx >= -1));
  /* if request wants to send, switching off the send direction is wrong */
  DEBUGASSERT((send_idx >= 0) || !Curl_req_want_send(data));

  conn->send_idx = send_idx;
  conn->recv_idx = recv_idx;

  /* without receiving, there should be not recv_size */
  DEBUGASSERT((conn->recv_idx >= 0) || (recv_size == -1));
  k->size = recv_size;
  k->header = !!conn->scheme->run->write_resp_hd;
  /* by default, we do not shutdown at the end of the transfer */
  k->shutdown = FALSE;
  k->shutdown_err_ignore = FALSE;

  /* The code sequence below is placed in this function because all necessary
     input is not always known in do_complete() as this function may be called
     after that */
  if(!k->header && (recv_size > 0))
    Curl_pgrsSetDownloadSize(data, recv_size);

  /* we want header and/or body, if neither then do not do this! */
  if(conn->scheme->run->write_resp_hd || !data->req.no_body) {
    if(conn->recv_idx != -1)
      CURL_REQ_SET_RECV(data);
    if(conn->send_idx != -1)
      CURL_REQ_SET_SEND(data);
  }
  CURL_TRC_M(data, "xfer_setup: recv_idx=%d, send_idx=%d",
             conn->recv_idx, conn->send_idx);
}

/**
 * @brief Set up a transfer that neither sends nor receives.
 *
 * @param[in,out] data  The transfer.
 */
void Curl_xfer_setup_nop(struct Curl_easy *data)
{
  xfer_setup(data, -1, -1, -1);
}

/**
 * @brief Set up a transfer that sends and receives on one socket.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     sockindex  Socket index used for both directions.
 * @param[in]     recv_size  Expected amount to receive, -1 if unknown.
 */
void Curl_xfer_setup_sendrecv(struct Curl_easy *data,
                              int8_t sockindex,
                              curl_off_t recv_size)
{
  xfer_setup(data, sockindex, sockindex, recv_size);
}

/**
 * @brief Set up a transfer that only sends.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     sockindex  Socket index to send on.
 */
void Curl_xfer_setup_send(struct Curl_easy *data,
                          int8_t sockindex)
{
  xfer_setup(data, sockindex, -1, -1);
}

/**
 * @brief Set up a transfer that only receives.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     sockindex  Socket index to receive on.
 * @param[in]     recv_size  Expected amount to receive, -1 if unknown.
 */
void Curl_xfer_setup_recv(struct Curl_easy *data,
                          int8_t sockindex,
                          curl_off_t recv_size)
{
  xfer_setup(data, -1, sockindex, recv_size);
}

/**
 * @brief Request a connection shutdown at the end of the transfer.
 *
 * @param[in,out] data           The transfer.
 * @param[in]     shutdown       TRUE to shut down the connection when done.
 * @param[in]     ignore_errors  TRUE to ignore errors during that shutdown.
 * @pre The transfer either only sends or only receives.
 */
void Curl_xfer_set_shutdown(struct Curl_easy *data,
                            bool shutdown,
                            bool ignore_errors)
{
  /* Shutdown should only be set when the transfer only sends or receives. */
  DEBUGASSERT(!shutdown ||
              (data->conn->send_idx < 0) || (data->conn->recv_idx < 0));
  data->req.shutdown = shutdown;
  data->req.shutdown_err_ignore = ignore_errors;
}

/**
 * @brief Write received response data to the client.
 *
 * If the protocol handler provides a write_resp function, it takes full
 * responsibility for the data. Otherwise everything is written as BODY
 * through the client writer chain. Writing the end-of-stream marker
 * successfully marks the download as done.
 *
 * @param[in,out] data    The transfer.
 * @param[in]     buf     Received data, not necessarily null-terminated.
 * @param[in]     blen    Number of bytes in @p buf.
 * @param[in]     is_eos  TRUE if this is the last data of the response.
 * @return CURLE_OK on success, otherwise the CURLcode from the handler or
 *         client write callbacks (for example CURLE_WRITE_ERROR).
 * @post On success with @p is_eos, req.eos_written and req.download_done
 *       are TRUE.
 */
CURLcode Curl_xfer_write_resp(struct Curl_easy *data,
                              const char *buf, size_t blen,
                              bool is_eos)
{
  CURLcode result = CURLE_OK;

  if(data->conn->scheme->run->write_resp) {
    /* protocol handlers offering this function take full responsibility
     * for writing all received download data to the client. */
    result = data->conn->scheme->run->write_resp(data, buf, blen, is_eos);
  }
  else {
    /* No special handling by protocol handler, write all received data
     * as BODY to the client. */
    if(blen || is_eos) {
      int cwtype = CLIENTWRITE_BODY;
      if(is_eos)
        cwtype |= CLIENTWRITE_EOS;
      result = Curl_client_write(data, cwtype, buf, blen);
    }
  }

  if(!result && is_eos) {
    /* If we wrote the EOS, we are definitely done */
    data->req.eos_written = TRUE;
    data->req.download_done = TRUE;
  }
  CURL_TRC_WRITE(data, "xfer_write_resp(len=%zu, eos=%d) -> %d",
                 blen, is_eos, (int)result);
  return result;
}

/**
 * @brief Tell if writing to the client is currently paused.
 *
 * @param[in] data  The transfer.
 * @return TRUE if the client writer is paused, FALSE otherwise.
 */
bool Curl_xfer_write_is_paused(struct Curl_easy *data)
{
  return Curl_cwriter_is_paused(data);
}

/**
 * @brief Write received response header data to the client.
 *
 * Protocol handlers with their own write_resp_hd function take full
 * responsibility; otherwise the bytes are written as normal response data.
 *
 * @param[in,out] data    The transfer.
 * @param[in]     hd0     Header bytes, must be null-terminated at
 *                        @p hdlen when a handler function is used.
 * @param[in]     hdlen   Number of header bytes.
 * @param[in]     is_eos  TRUE if this is the last data of the response.
 * @return CURLE_OK on success, otherwise the CURLcode from the writer.
 */
CURLcode Curl_xfer_write_resp_hd(struct Curl_easy *data,
                                 const char *hd0, size_t hdlen, bool is_eos)
{
  if(data->conn->scheme->run->write_resp_hd) {
    DEBUGASSERT(!hd0[hdlen]); /* null-terminated */
    /* protocol handlers offering this function take full responsibility
     * for writing all received download data to the client. */
    return data->conn->scheme->run->write_resp_hd(data, hd0, hdlen, is_eos);
  }
  /* No special handling by protocol handler, write as response bytes */
  return Curl_xfer_write_resp(data, hd0, hdlen, is_eos);
}

/**
 * @brief Signal the end of response writing to the client writers.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     premature  Unused, whether the transfer ended early.
 * @return CURLE_OK, or the error from flushing the output writer.
 */
CURLcode Curl_xfer_write_done(struct Curl_easy *data, bool premature)
{
  (void)premature;
  return Curl_cw_out_done(data);
}

/**
 * @brief Tell if buffered send data still needs flushing.
 *
 * @param[in] data  The transfer.
 * @return TRUE if the send side of the connection has unflushed data.
 */
bool Curl_xfer_needs_flush(struct Curl_easy *data)
{
  return Curl_conn_needs_flush(data, data->conn->send_idx);
}

/**
 * @brief Flush buffered send data on the connection.
 *
 * @param[in,out] data  The transfer.
 * @return CURLE_OK, CURLE_AGAIN if not everything could be flushed yet,
 *         or another CURLcode on a send failure.
 */
CURLcode Curl_xfer_flush(struct Curl_easy *data)
{
  return Curl_conn_flush(data, data->conn->send_idx);
}

/**
 * @brief Send data on the transfer's send socket.
 *
 * CURLE_AGAIN from the connection is turned into success with zero bytes
 * written. Bytes sent are added to the request size info.
 *
 * @param[in,out] data       The transfer.
 * @param[in]     buf        Data to send.
 * @param[in]     blen       Number of bytes in @p buf.
 * @param[in]     eos        TRUE if this is the last data to send.
 * @param[out]    pnwritten  Number of bytes accepted; may be less than
 *                           @p blen or 0.
 * @return CURLE_OK on success (check @p pnwritten) or CURLE_AGAIN
 *         translated, otherwise the send error such as CURLE_SEND_ERROR.
 * @pre data->conn is set.
 */
CURLcode Curl_xfer_send(struct Curl_easy *data,
                        const void *buf, size_t blen, bool eos,
                        size_t *pnwritten)
{
  CURLcode result;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  result = Curl_conn_send(data, data->conn->send_idx,
                          buf, blen, eos, pnwritten);
  if(result == CURLE_AGAIN) {
    result = CURLE_OK;
    *pnwritten = 0;
  }
  else if(!result && *pnwritten)
    data->info.request_size += *pnwritten;

  DEBUGF(infof(data, "Curl_xfer_send(len=%zu, eos=%d) -> %d, %zu",
               blen, eos, (int)result, *pnwritten));
  return result;
}

/**
 * @brief Receive data on the transfer's receive socket.
 *
 * The read size is capped to the configured CURLOPT_BUFFERSIZE.
 *
 * @param[in,out] data    The transfer.
 * @param[out]    buf     Buffer for the received data.
 * @param[in]     blen    Capacity of @p buf in bytes.
 * @param[out]    pnrcvd  Number of bytes received.
 * @return CURLE_OK on success, CURLE_AGAIN if nothing is available now,
 *         or another CURLcode such as CURLE_RECV_ERROR.
 * @pre data->conn is set.
 */
CURLcode Curl_xfer_recv(struct Curl_easy *data,
                        char *buf, size_t blen,
                        size_t *pnrcvd)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  DEBUGASSERT(data->set.buffer_size > 0);

  if(curlx_uitouz(data->set.buffer_size) < blen)
    blen = curlx_uitouz(data->set.buffer_size);
  return Curl_conn_recv(data, data->conn->recv_idx, buf, blen, pnrcvd);
}

/**
 * @brief Tell the connection filters that sending is finished.
 *
 * @param[in,out] data  The transfer.
 * @return Always CURLE_OK.
 */
CURLcode Curl_xfer_send_close(struct Curl_easy *data)
{
  Curl_conn_ev_data_done_send(data);
  return CURLE_OK;
}

/**
 * @brief Tell if the transfer cannot make progress because of pauses.
 *
 * The transfer is blocked if every direction it wants is paused.
 *
 * @param[in] data  The transfer.
 * @return TRUE if all wanted directions are paused, FALSE otherwise.
 */
bool Curl_xfer_is_blocked(struct Curl_easy *data)
{
  bool want_send = CURL_REQ_WANT_SEND(data);
  bool want_recv = CURL_REQ_WANT_RECV(data);
  if(!want_send)
    return want_recv && Curl_xfer_recv_is_paused(data);
  else if(!want_recv)
    return want_send && Curl_xfer_send_is_paused(data);
  else
    return Curl_xfer_recv_is_paused(data) && Curl_xfer_send_is_paused(data);
}

/**
 * @brief Tell if sending is paused or blocked by the upload rate limit.
 *
 * @param[in] data  The transfer.
 * @return TRUE if the upload rate limiter is blocking, FALSE otherwise.
 */
bool Curl_xfer_send_is_paused(struct Curl_easy *data)
{
  return Curl_rlimit_is_blocked(&data->progress.ul.rlimit);
}

/**
 * @brief Tell if receiving is paused or blocked by the download rate limit.
 *
 * @param[in] data  The transfer.
 * @return TRUE if the download rate limiter is blocking, FALSE otherwise.
 */
bool Curl_xfer_recv_is_paused(struct Curl_easy *data)
{
  return Curl_rlimit_is_blocked(&data->progress.dl.rlimit);
}

/**
 * @brief Pause or unpause sending for the transfer.
 *
 * Unpausing also resumes a paused client reader and resets the speed
 * records.
 *
 * @param[in,out] data    The transfer.
 * @param[in]     enable  TRUE to pause, FALSE to unpause.
 * @return CURLE_OK, or the error from unpausing the client reader.
 */
CURLcode Curl_xfer_pause_send(struct Curl_easy *data, bool enable)
{
  CURLcode result = CURLE_OK;
  Curl_rlimit_block(&data->progress.ul.rlimit, enable, Curl_pgrs_now(data));
  if(!enable && Curl_creader_is_paused(data))
    result = Curl_creader_unpause(data);
  Curl_pgrsSendPause(data, enable);
  return result;
}

/**
 * @brief Pause or unpause receiving for the transfer.
 *
 * Unpausing also resumes a paused client writer, notifies the connection
 * filters and resets the speed records.
 *
 * @param[in,out] data    The transfer.
 * @param[in]     enable  TRUE to pause, FALSE to unpause.
 * @return CURLE_OK, or the error from unpausing the client writer (for
 *         instance buffered data that fails to be delivered).
 */
CURLcode Curl_xfer_pause_recv(struct Curl_easy *data, bool enable)
{
  CURLcode result = CURLE_OK;
  Curl_rlimit_block(&data->progress.dl.rlimit, enable, Curl_pgrs_now(data));
  if(!enable && Curl_cwriter_is_paused(data))
    result = Curl_cwriter_unpause(data);
  Curl_conn_ev_data_pause(data, enable);
  Curl_pgrsRecvPause(data, enable);
  return result;
}

/**
 * @brief Tell if the transfer's origin is reached over a secure scheme.
 *
 * Forward proxy connections count as not secure, since https: and other
 * SSL based URLs never use a forward proxy for the origin.
 *
 * @param[in] data  The transfer.
 * @return Non-zero (the PROTOPT_SSL flag) if the origin scheme uses SSL,
 *         FALSE (0) otherwise.
 */
bool Curl_xfer_is_secure(struct Curl_easy *data)
{
#ifndef CURL_DISABLE_PROXY
  if(data->conn && data->conn->bits.origin_is_proxy) {
    /* talking to a forward proxy, not secure. we do not use
     * a forward proxy for https: and other 's' URLs. Let's just check that
     * this did not fail somewhere. */
    DEBUGASSERT(!(data->state.origin->scheme->flags & PROTOPT_SSL));
    return FALSE;
  }
#endif
  return (data->state.origin->scheme->flags & PROTOPT_SSL);
}
/** @} */
