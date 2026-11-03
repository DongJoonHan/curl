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
 * @file request.c
 * @brief Per-request state handling for a transfer (struct SingleRequest).
 *
 * Each Curl_easy handle embeds a SingleRequest (@c data->req) holding the
 * state of the request that is currently being performed on it: byte
 * counters, header bookkeeping, end-of-stream flags, the send buffer and
 * the I/O interest flags. This file implements its life cycle (init,
 * start, soft/hard reset, done, free) and the logic that moves request
 * bytes from the client readers into the send buffer and out onto the
 * connection, including flow control and upload completion.
 *
 * @note All functions here operate on a single easy handle and are not
 *       thread-safe; the handle must only be used by one thread at a time.
 *
 * @defgroup request Request state and sending
 * @brief Life cycle and send path of the per-transfer SingleRequest.
 * @{
 */
#include "curl_setup.h"

#include "urldata.h"
#include "cfilters.h"
#include "curlx/dynbuf.h"
#include "progress.h"
#include "request.h"
#include "sendf.h"
#include "curl_trc.h"
#include "transfer.h"
#include "url.h"
#include "curlx/strparse.h"

/**
 * @brief Initialize a request struct to the all-zero state.
 *
 * Sets every member of @p req to zero. It does not release anything, so
 * it must only be used on memory that holds no live resources, e.g. when a
 * handle is created.
 *
 * @param[out] req  The request struct to initialize.
 *
 * @warning Any previously allocated members (headers, send buffer) are
 *          leaked if @p req was in use before.
 * @see Curl_req_free(), Curl_req_hard_reset()
 */
void Curl_req_init(struct SingleRequest *req)
{
  memset(req, 0, sizeof(*req));
}

/**
 * @brief Reset the per-attempt state of a request, keeping the URL data.
 *
 * Clears the done/EOS flags, the byte and header counters and the
 * negotiated HTTP versions, frees the cached auth headers, restarts the
 * client reader/writer stack and (re)creates or resets the send buffer so
 * it matches the configured upload buffer size. Used when a request is
 * started or retried on the same handle.
 *
 * @param[in,out] req   The request to reset.
 * @param[in,out] data  The easy handle owning @p req.
 *
 * @return CURLE_OK on success.
 * @return Any error from Curl_client_start() when the client readers or
 *         writers cannot be started.
 *
 * @note The send buffer is reallocated if the upload buffer size option
 *       changed since the buffer was created.
 * @see Curl_req_start(), Curl_req_hard_reset()
 */
CURLcode Curl_req_soft_reset(struct SingleRequest *req,
                             struct Curl_easy *data)
{
  CURLcode result;

  req->done = FALSE;
  req->upload_done = FALSE;
  req->upload_aborted = FALSE;
  req->download_done = FALSE;
  req->eos_written = FALSE;
  req->eos_read = FALSE;
  req->eos_sent = FALSE;
  req->ignorebody = FALSE;
  req->shutdown = FALSE;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->header = FALSE;
  req->headerline = 0;
  req->headerbytecount = 0;
  req->allheadercount = 0;
  req->deductheadercount = 0;
  req->httpversion_sent = 0;
  req->httpversion = 0;
  req->sendbuf_hds_len = 0;

  curlx_safefree(req->hd_auth);
#ifndef CURL_DISABLE_PROXY
  curlx_safefree(req->hd_proxy_auth);
#endif

  result = Curl_client_start(data);
  if(result)
    return result;

  if(!req->sendbuf_init) {
    Curl_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                    BUFQ_OPT_SOFT_LIMIT);
    req->sendbuf_init = TRUE;
  }
  else {
    Curl_bufq_reset(&req->sendbuf);
    if(data->set.upload_buffer_size != req->sendbuf.chunk_size) {
      Curl_bufq_free(&req->sendbuf);
      Curl_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                      BUFQ_OPT_SOFT_LIMIT);
    }
  }

  return CURLE_OK;
}

/**
 * @brief Start a new request: stamp the start time and soft-reset.
 *
 * @param[in,out] req   The request to start.
 * @param[in,out] data  The easy handle owning @p req.
 *
 * @return CURLE_OK on success, otherwise the error from
 *         Curl_req_soft_reset().
 * @post @c req->start holds the current progress timestamp.
 */
CURLcode Curl_req_start(struct SingleRequest *req,
                        struct Curl_easy *data)
{
  req->start = *Curl_pgrs_now(data);
  return Curl_req_soft_reset(req, data);
}

/* forward declaration, used by Curl_req_done() */
static CURLcode req_flush(struct Curl_easy *data);

/**
 * @brief Finish a request.
 *
 * Unless the request was aborted, a last attempt is made to flush any
 * pending send data (errors from that are ignored). The client
 * reader/writer stack is then reset.
 *
 * @param[in,out] req      The request (unused, kept for API symmetry).
 * @param[in,out] data     The easy handle owning the request.
 * @param[in]     aborted  TRUE if the transfer is being aborted, in which
 *                         case no flush is attempted.
 *
 * @return Always CURLE_OK.
 */
CURLcode Curl_req_done(struct SingleRequest *req,
                       struct Curl_easy *data, bool aborted)
{
  (void)req;
  if(!aborted)
    (void)req_flush(data);
  Curl_client_reset(data);
  return CURLE_OK;
}

/**
 * @brief Completely reset a request so the handle can be reused.
 *
 * Frees the allocated strings (new URL, auth headers, cookie host),
 * resets the client stack and the send buffer, destroys resolver data and
 * restores all counters, flags and sizes to their initial values. Unlike
 * Curl_req_init() this keeps the send buffer allocation and other state
 * that must survive, so the struct cannot simply be memset().
 *
 * @param[in,out] req   The request to reset.
 * @param[in,out] data  The easy handle owning @p req.
 *
 * @post Rate limits for both directions are unblocked, @c req->no_body
 *       follows CURLOPT_NOBODY and size/maxdownload are -1 (unknown).
 * @see Curl_req_soft_reset(), Curl_req_free()
 */
void Curl_req_hard_reset(struct SingleRequest *req, struct Curl_easy *data)
{
  struct curltime t0 = { 0, 0 };

  curlx_safefree(req->newurl);
  curlx_safefree(req->hd_auth);
#ifndef CURL_DISABLE_PROXY
  curlx_safefree(req->hd_proxy_auth);
#endif
#ifndef CURL_DISABLE_COOKIES
  curlx_safefree(req->cookiehost);
#endif
  Curl_client_reset(data);
  if(req->sendbuf_init)
    Curl_bufq_reset(&req->sendbuf);

  /* clear any resolve data */
  Curl_resolv_destroy_all(data);
  /* Can no longer memset() this struct as we need to keep some state */
  req->size = -1;
  req->maxdownload = -1;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->start = t0;
  req->headerbytecount = 0;
  req->allheadercount = 0;
  req->deductheadercount = 0;
  req->headerline = 0;
  req->offset = 0;
  req->httpcode = 0;
  req->io_flags = 0;
  req->upgr101 = UPGR101_NONE;
  req->sendbuf_hds_len = 0;
  req->timeofdoc = 0;
  req->location = NULL;
  req->newurl = NULL;
#ifndef CURL_DISABLE_COOKIES
  req->setcookies = 0;
#endif
  req->header = FALSE;
  req->content_range = FALSE;
  req->download_done = FALSE;
  req->eos_written = FALSE;
  req->eos_read = FALSE;
  req->eos_sent = FALSE;
  req->rewind_read = FALSE;
  req->upload_done = FALSE;
  req->upload_aborted = FALSE;
  req->ignorebody = FALSE;
  req->http_bodyless = FALSE;
  req->chunk = FALSE;
  req->resp_trailer = FALSE;
  req->ignore_cl = FALSE;
  req->upload_chunky = FALSE;
  req->no_body = data->set.opt_no_body;
  req->authneg = FALSE;
  req->shutdown = FALSE;
  /* Unpause all directions */
  Curl_rlimit_block(&data->progress.dl.rlimit, FALSE, &t0);
  Curl_rlimit_block(&data->progress.ul.rlimit, FALSE, &t0);
}

/**
 * @brief Release all resources held by a request.
 *
 * Frees the new-URL and auth header strings, the send buffer (if it was
 * initialized) and cleans up the client reader/writer stack.
 *
 * @param[in,out] req   The request to free.
 * @param[in,out] data  The easy handle owning @p req.
 *
 * @warning @p req must not be used afterwards without Curl_req_init().
 */
void Curl_req_free(struct SingleRequest *req, struct Curl_easy *data)
{
  curlx_safefree(req->newurl);
  curlx_safefree(req->hd_auth);
#ifndef CURL_DISABLE_PROXY
  curlx_safefree(req->hd_proxy_auth);
#endif
  if(req->sendbuf_init)
    Curl_bufq_free(&req->sendbuf);
  Curl_client_cleanup(data);
}

/**
 * @internal
 * @brief Send request bytes on the transfer connection.
 *
 * Applies the maximum send speed limit to the body part (headers are not
 * counted), detects when the last chunk of an upload is being sent and
 * marks end-of-stream accordingly. Successfully written bytes are reported
 * to the debug callback (header and data separately) and added to the
 * upload counters.
 *
 * @param[in,out] data      The easy handle.
 * @param[in]     buf       Bytes to send, headers first, then body.
 * @param[in]     blen      Number of bytes in @p buf.
 * @param[in]     hds_len   How many leading bytes of @p buf are headers,
 *                          must be <= @p blen.
 * @param[out]    pnwritten Number of bytes actually sent (may be less than
 *                          @p blen).
 *
 * @return CURLE_OK on success.
 * @return CURLE_AGAIN if the connection cannot take data right now.
 * @return Other CURLcode errors from Curl_xfer_send().
 *
 * @note Debug builds honor the CURL_SMALLREQSEND environment variable to
 *       force short initial body sends.
 * @post @c data->req.eos_sent is set when the final chunk was fully sent.
 */
static CURLcode xfer_send(struct Curl_easy *data,
                          const char *buf, size_t blen,
                          size_t hds_len, size_t *pnwritten)
{
  CURLcode result = CURLE_OK;
  bool eos = FALSE;

  *pnwritten = 0;
  DEBUGASSERT(hds_len <= blen);
#ifdef DEBUGBUILD
  {
    /* Allow debug builds to override this logic to force short initial
       sends */
    size_t body_len = blen - hds_len;
    if(body_len) {
      const char *p = getenv("CURL_SMALLREQSEND");
      if(p) {
        curl_off_t body_small;
        if(!curlx_str_number(&p, &body_small, body_len))
          blen = hds_len + (size_t)body_small;
      }
    }
  }
#endif
  /* Make sure this does not send more body bytes than what the max send
     speed says. The headers do not count to the max speed. */
  if(data->set.max_send_speed) {
    size_t body_bytes = blen - hds_len;
    if((curl_off_t)body_bytes > data->set.max_send_speed)
      blen = hds_len + (size_t)data->set.max_send_speed;
  }

  if(data->req.eos_read &&
    (Curl_bufq_is_empty(&data->req.sendbuf) ||
     Curl_bufq_len(&data->req.sendbuf) == blen)) {
    DEBUGF(infof(data, "sending last upload chunk of %zu bytes", blen));
    eos = TRUE;
  }
  result = Curl_xfer_send(data, buf, blen, eos, pnwritten);
  if(!result) {
    if(eos && (blen == *pnwritten))
      data->req.eos_sent = TRUE;
    if(*pnwritten) {
      if(hds_len)
        Curl_debug(data, CURLINFO_HEADER_OUT, buf,
                   CURLMIN(hds_len, *pnwritten));
      if(*pnwritten > hds_len) {
        size_t body_len = *pnwritten - hds_len;
        Curl_debug(data, CURLINFO_DATA_OUT, buf + hds_len, body_len);
        data->req.writebytecount += body_len;
        Curl_pgrs_upload_inc(data, body_len);
      }
    }
  }
  return result;
}

/**
 * @internal
 * @brief Send the contents of the request send buffer.
 *
 * Repeatedly peeks at the buffer, sends what it can and drops the sent
 * bytes. Stops at the first error or when a send was only partial (e.g.
 * the network blocks or a speed limit applies). The count of pending
 * header bytes in the buffer is kept up to date.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK if no error occurred, even if data remains buffered.
 * @return Any error returned by xfer_send().
 */
static CURLcode req_send_buffer_flush(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  const unsigned char *buf;
  size_t blen;

  while(Curl_bufq_peek(&data->req.sendbuf, &buf, &blen)) {
    size_t nwritten, hds_len = CURLMIN(data->req.sendbuf_hds_len, blen);
    result = xfer_send(data, (const char *)buf, blen, hds_len, &nwritten);
    if(result)
      break;

    Curl_bufq_skip(&data->req.sendbuf, nwritten);
    if(hds_len) {
      data->req.sendbuf_hds_len -= CURLMIN(hds_len, nwritten);
    }
    /* leave if we could not send all. Maybe network blocking or
     * speed limits on transfer */
    if(nwritten < blen)
      break;
  }
  return result;
}

/**
 * @internal
 * @brief Mark the upload direction as finished.
 *
 * Clears the send interest, records the post-transfer timer once the
 * request was sent, informs the client readers and logs a summary. On an
 * aborted upload the send buffer is discarded. Finally closes the send
 * direction of the transfer if the protocol requires it.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK on success, else the error from
 *         Curl_xfer_send_close().
 * @pre @c data->req.upload_done must be FALSE.
 * @post @c data->req.upload_done is TRUE.
 */
static CURLcode req_set_upload_done(struct Curl_easy *data)
{
  DEBUGASSERT(!data->req.upload_done);
  data->req.upload_done = TRUE;
  CURL_REQ_CLEAR_SEND(data);

  if(data->mstate >= MSTATE_DID)
    Curl_pgrsTime(data, TIMER_POSTRANSFER);
  Curl_creader_done(data, data->req.upload_aborted);

  if(data->req.upload_aborted) {
    Curl_bufq_reset(&data->req.sendbuf);
    if(data->req.writebytecount)
      infof(data, "abort upload after having sent %" FMT_OFF_T " bytes",
            data->req.writebytecount);
    else
      infof(data, "abort upload");
  }
  else if(data->req.writebytecount)
    infof(data, "upload completely sent off: %" FMT_OFF_T " bytes",
          data->req.writebytecount);
  else if(!data->req.download_done) {
    DEBUGASSERT(Curl_bufq_is_empty(&data->req.sendbuf));
    infof(data, Curl_creader_total_length(data) ?
          "We are completely uploaded and fine" :
          "Request completely sent off");
  }

  return Curl_xfer_send_close(data);
}

/**
 * @internal
 * @brief Flush all pending request data and finish the upload if possible.
 *
 * Sends buffered data, flushes connection filters with pending output,
 * emits the final empty end-of-stream send if needed and, once everything
 * is out, optionally shuts down the send direction and marks the upload
 * done.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK if all pending data was handled.
 * @return CURLE_AGAIN if data remains buffered or a shutdown is still in
 *         progress; call again when the socket is writable.
 * @return CURLE_FAILED_INIT if @p data is NULL or has no connection.
 * @return Other CURLcode errors from sending or shutting down.
 */
static CURLcode req_flush(struct Curl_easy *data)
{
  CURLcode result;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  if(!Curl_bufq_is_empty(&data->req.sendbuf)) {
    result = req_send_buffer_flush(data);
    if(result)
      return result;
    if(!Curl_bufq_is_empty(&data->req.sendbuf)) {
      DEBUGF(infof(data, "Curl_req_flush(len=%zu) -> EAGAIN",
                   Curl_bufq_len(&data->req.sendbuf)));
      return CURLE_AGAIN;
    }
  }
  else if(Curl_xfer_needs_flush(data)) {
    DEBUGF(infof(data, "Curl_req_flush(), xfer send_pending"));
    return Curl_xfer_flush(data);
  }

  if(data->req.eos_read && !data->req.eos_sent) {
    char tmp = 0;
    size_t nwritten;
    result = xfer_send(data, &tmp, 0, 0, &nwritten);
    if(result)
      return result;
    DEBUGASSERT(data->req.eos_sent);
  }

  if(!data->req.upload_done && data->req.eos_read && data->req.eos_sent) {
    DEBUGASSERT(Curl_bufq_is_empty(&data->req.sendbuf));
    if(data->req.shutdown) {
      bool done;
      result = Curl_xfer_send_shutdown(data, &done);
      if(result && data->req.shutdown_err_ignore) {
        infof(data, "Shutdown send direction error: %d. Broken server? "
              "Proceeding as if everything is ok.", (int)result);
        result = CURLE_OK;
        done = TRUE;
      }

      if(result)
        return result;
      if(!done)
        return CURLE_AGAIN;
    }
    return req_set_upload_done(data);
  }
  return CURLE_OK;
}

/**
 * @internal
 * @brief Bufq reader callback that pulls upload data from the client.
 *
 * Used by Curl_bufq_sipn(). Reads from the client reader chain and sets
 * the end-of-stream flag of the request when the reader signals EOS.
 *
 * @param[in]  reader_ctx  The struct Curl_easy to read for.
 * @param[out] buf         Buffer to fill.
 * @param[in]  buflen      Capacity of @p buf.
 * @param[out] pnread      Number of bytes placed into @p buf.
 *
 * @return CURLE_OK on success, else an error from Curl_client_read().
 */
static CURLcode add_from_client(void *reader_ctx,
                                unsigned char *buf, size_t buflen,
                                size_t *pnread)
{
  struct Curl_easy *data = reader_ctx;
  CURLcode result;
  bool eos;

  result = Curl_client_read(data, (char *)buf, buflen, pnread, &eos);
  if(!result && eos)
    data->req.eos_read = TRUE;
  return result;
}

/**
 * @internal
 * @brief Append bytes to the request send buffer.
 *
 * @param[in,out] data     The easy handle.
 * @param[in]     buf      Bytes to append.
 * @param[in]     blen     Length of @p buf.
 * @param[in]     hds_len  How many of the appended bytes are headers.
 *
 * @return CURLE_OK on success, else the error from the buffer queue.
 * @note The buffer has a soft limit, so all @p blen bytes are always
 *       accepted.
 */
static CURLcode req_send_buffer_add(struct Curl_easy *data,
                                    const char *buf, size_t blen,
                                    size_t hds_len)
{
  CURLcode result = CURLE_OK;
  size_t n;
  result = Curl_bufq_cwrite(&data->req.sendbuf, buf, blen, &n);
  if(result)
    return result;
  /* We rely on a SOFTLIMIT on sendbuf, so it can take all data in */
  DEBUGASSERT(n == blen);
  data->req.sendbuf_hds_len += hds_len;
  return CURLE_OK;
}

/**
 * @brief Send a prepared request (headers) to the server.
 *
 * If the send buffer is empty, there is no request body and the headers
 * fit in one buffer chunk, they are sent directly. Otherwise (or for a
 * remainder after a partial send) the bytes are buffered, together with
 * body data as room allows, and flushed by Curl_req_send_more().
 *
 * @param[in,out] data         The easy handle with a connection.
 * @param[in]     req          Dynamic buffer holding the request headers.
 * @param[in]     httpversion  HTTP version being sent, stored in
 *                             @c req.httpversion_sent.
 *
 * @return CURLE_OK on success, including when data is still buffered.
 * @return CURLE_FAILED_INIT if @p data is NULL or has no connection.
 * @return Other CURLcode errors from sending or reading the body.
 *
 * @note Requests larger than the buffer chunk size are never sent
 *       directly, since a retried blocked send must not shrink in length.
 */
CURLcode Curl_req_send(struct Curl_easy *data, struct dynbuf *req,
                       unsigned char httpversion)
{
  CURLcode result;
  const char *buf;
  size_t blen, nwritten;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  data->req.httpversion_sent = httpversion;
  buf = curlx_dyn_ptr(req);
  blen = curlx_dyn_len(req);
  /* if the sendbuf is empty and the request without body and
   * the length to send fits info a sendbuf chunk, we send it directly.
   * If `blen` is larger than `chunk_size`, we can not. Because we
   * might have to retry a blocked send later from sendbuf and that
   * would result in retry sends with a shrunken length. That is trouble. */
  if(Curl_bufq_is_empty(&data->req.sendbuf) &&
     !Curl_creader_total_length(data) &&
     (blen <= data->req.sendbuf.chunk_size)) {
    data->req.eos_read = TRUE;
    result = xfer_send(data, buf, blen, blen, &nwritten);
    if(result)
      return result;
    buf += nwritten;
    blen -= nwritten;
    if(!blen) {
      result = req_set_upload_done(data);
      if(result)
        return result;
    }
  }

  if(blen) {
    /* Either we have a request body, or we could not send the complete
     * request in one go. Buffer the remainder and try to add as much
     * body bytes as room is left in the buffer. Then flush. */
    result = req_send_buffer_add(data, buf, blen, blen);
    if(result)
      return result;

    return Curl_req_send_more(data);
  }
  return CURLE_OK;
}

/**
 * @brief Check whether the request send buffer holds no data.
 *
 * @param[in] data  The easy handle.
 *
 * @return TRUE if the buffer was never initialized or is empty.
 * @return FALSE if bytes are waiting to be sent.
 */
bool Curl_req_sendbuf_empty(struct Curl_easy *data)
{
  return !data->req.sendbuf_init || Curl_bufq_is_empty(&data->req.sendbuf);
}

/**
 * @brief Tell whether the transfer wants to send more data.
 *
 * True when the request is not done, the upload is not blocked by a rate
 * limit and either the send interest flag is set, the send buffer has
 * data or the connection has output pending.
 *
 * @param[in] data  The easy handle.
 *
 * @return TRUE if the socket should be polled for writability.
 */
bool Curl_req_want_send(struct Curl_easy *data)
{
  /* Not done and upload not blocked and either one of
   * - REQ_IO_SEND
   * - request has buffered data to send
   * - connection has pending data to send */
  return !data->req.done &&
         !Curl_rlimit_is_blocked(&data->progress.ul.rlimit) &&
         (CURL_REQ_WANT_SEND(data) ||
          !Curl_req_sendbuf_empty(data) ||
          Curl_xfer_needs_flush(data));
}

/**
 * @brief Tell whether the transfer wants to receive more data.
 *
 * @param[in] data  The easy handle.
 *
 * @return TRUE if the request is not done, the download is not blocked by
 *         a rate limit and the receive interest flag is set.
 */
bool Curl_req_want_recv(struct Curl_easy *data)
{
  /* Not done and download not blocked and want RECV */
  return !data->req.done &&
         !Curl_rlimit_is_blocked(&data->progress.dl.rlimit) &&
         CURL_REQ_WANT_RECV(data);
}

/**
 * @brief Tell whether the upload has been fully sent.
 *
 * @param[in] data  The easy handle.
 *
 * @return TRUE if the upload is marked done and nothing is left to send.
 */
bool Curl_req_done_sending(struct Curl_easy *data)
{
  return data->req.upload_done && !Curl_req_want_send(data);
}

/**
 * @brief Read more upload data from the client and flush the send buffer.
 *
 * Fills the send buffer from the client readers (unless aborted, at EOS,
 * paused or the buffer is full), then flushes. A blocked flush
 * (CURLE_AGAIN) is not an error here.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK on success or if sending would block.
 * @return Other CURLcode errors from reading or sending.
 */
CURLcode Curl_req_send_more(struct Curl_easy *data)
{
  CURLcode result;

  /* Fill our send buffer if more from client can be read. */
  if(!data->req.upload_aborted &&
     !data->req.eos_read &&
     !Curl_xfer_send_is_paused(data) &&
     !Curl_bufq_is_full(&data->req.sendbuf)) {
    size_t nread;
    result = Curl_bufq_sipn(&data->req.sendbuf, 0,
                            add_from_client, data, &nread);
    if(result && result != CURLE_AGAIN)
      return result;
  }

  result = req_flush(data);
  if(result == CURLE_AGAIN)
    result = CURLE_OK;

  return result;
}

/**
 * @brief Abort the upload direction of the request.
 *
 * Discards buffered data, flags the upload as aborted and finishes it.
 * Does nothing if the upload is already done.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK on success, else the error from closing the send side.
 * @post @c data->req.upload_done and @c upload_aborted are TRUE.
 */
CURLcode Curl_req_abort_sending(struct Curl_easy *data)
{
  if(!data->req.upload_done) {
    Curl_bufq_reset(&data->req.sendbuf);
    data->req.upload_aborted = TRUE;
    CURL_REQ_CLEAR_SEND(data);
    return req_set_upload_done(data);
  }
  return CURLE_OK;
}

/**
 * @brief Stop all sending and receiving for the request.
 *
 * Aborts the upload if the transfer still wanted to send and clears all
 * I/O interest bits, including PAUSE and HOLD.
 *
 * @param[in,out] data  The easy handle.
 *
 * @return CURLE_OK on success, else the error from
 *         Curl_req_abort_sending().
 * @note Client writes may still be paused on the receive side; those
 *       bits are kept intact by this operation.
 */
CURLcode Curl_req_stop_send_recv(struct Curl_easy *data)
{
  /* stop receiving and ALL sending as well, including PAUSE and HOLD.
   * We might still be paused on receive client writes though, so
   * keep those bits around. */
  CURLcode result = CURLE_OK;
  if(CURL_REQ_WANT_SEND(data))
    result = Curl_req_abort_sending(data);
  CURL_REQ_CLEAR_IO(data);
  return result;
}

/** @} */
