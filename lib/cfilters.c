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
 * @file cfilters.c
 * @brief Connection filter chain: default methods and chain management.
 *
 * A connection filter (struct Curl_cfilter) is one layer of a connection,
 * for example TCP/UDP socket, TLS, HTTP/2 or an HTTP proxy tunnel. Each
 * connection has up to two filter chains (indexed by sockindex), stored as
 * singly linked lists with the top-most (closest to the application)
 * filter first. Every filter implements the callbacks of its
 * struct Curl_cftype; the Curl_cf_def_*() functions here are the default
 * implementations that simply delegate to the next filter in the chain.
 *
 * This file also provides the Curl_conn_*() helpers which dispatch
 * operations (connect, send, recv, poll, query, control events) to the
 * filter chains of a connection.
 *
 * @note Filters are not thread-safe. A chain belongs to one connection,
 *       which is used by one transfer at a time.
 * @see cfilters.h
 * @defgroup cfilters Connection filters
 * @brief Layered connection handling.
 */
#include "curl_setup.h"

#include "urldata.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "url.h"
#include "curl_trc.h"
#include "progress.h"
#include "select.h"
#include "curlx/strparse.h"

/**
 * @brief Default connect callback: connect the next filter, then mark done.
 *
 * Delegates to the next filter first. Once that reports completion (or if
 * there is none), this filter is marked as connected.
 *
 * @param[in,out] cf   Filter being connected.
 * @param[in,out] data Easy handle of the transfer.
 * @param[out]    done Set TRUE when the filter (and everything below it)
 *                     is connected, FALSE while still in progress.
 * @return CURLE_OK on success or while still in progress (check @p done),
 *         otherwise the error code returned by the next filter.
 * @post On success with @p done TRUE, cf->connected is TRUE.
 */
CURLcode Curl_cf_def_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data, bool *done)
{
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(cf->next) {
    result = cf->next->cft->do_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  cf->connected = TRUE;
  *done = TRUE;
  return CURLE_OK;
}

/**
 * @brief Default shutdown callback: nothing to do, report done.
 * @param[in,out] cf   Filter being shut down (unused).
 * @param[in,out] data Easy handle (unused).
 * @param[out]    done Always set to TRUE.
 * @return Always CURLE_OK.
 */
CURLcode Curl_cf_def_shutdown(struct Curl_cfilter *cf,
                              struct Curl_easy *data, bool *done)
{
  (void)cf;
  (void)data;
  *done = TRUE;
  return CURLE_OK;
}

/**
 * @brief Default pollset callback: add no sockets to the pollset.
 * @param[in]     cf   Filter (unused).
 * @param[in]     data Easy handle (unused).
 * @param[in,out] ps   Pollset (unchanged).
 * @return Always CURLE_OK.
 */
CURLcode Curl_cf_def_adjust_pollset(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct easy_pollset *ps)
{
  /* NOP */
  (void)cf;
  (void)data;
  (void)ps;
  return CURLE_OK;
}

/**
 * @brief Default data-pending callback: ask the next filter.
 * @param[in] cf   Filter being queried.
 * @param[in] data Easy handle of the transfer.
 * @return TRUE if a filter further down holds buffered data that can be
 *         read without socket I/O, FALSE if none or no next filter.
 */
bool Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

/**
 * @brief Default send callback: pass the data to the next filter.
 * @param[in,out] cf       Filter being used.
 * @param[in,out] data     Easy handle of the transfer.
 * @param[in]     buf      Data to send.
 * @param[in]     len      Number of bytes in @p buf.
 * @param[in]     eos      TRUE if this is the end of the stream.
 * @param[out]    pnwritten Number of bytes accepted by the chain.
 * @return Result of the next filter, or CURLE_RECV_ERROR (sic) with
 *         *pnwritten set to 0 if there is no next filter.
 */
CURLcode Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const uint8_t *buf, size_t len, bool eos,
                          size_t *pnwritten)
{
  if(cf->next)
    return cf->next->cft->do_send(cf->next, data, buf, len, eos, pnwritten);
  *pnwritten = 0;
  return CURLE_RECV_ERROR;
}

/**
 * @brief Default receive callback: read from the next filter.
 * @param[in,out] cf     Filter being used.
 * @param[in,out] data   Easy handle of the transfer.
 * @param[out]    buf    Buffer to receive data.
 * @param[in]     len    Size of @p buf in bytes.
 * @param[out]    pnread Number of bytes read.
 * @return Result of the next filter, or CURLE_SEND_ERROR (sic) with
 *         *pnread set to 0 if there is no next filter.
 */
CURLcode Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, size_t *pnread)
{
  if(cf->next)
    return cf->next->cft->do_recv(cf->next, data, buf, len, pnread);
  *pnread = 0;
  return CURLE_SEND_ERROR;
}

/**
 * @brief Default liveness callback: ask the next filter.
 * @param[in,out] cf            Filter being queried.
 * @param[in,out] data          Easy handle of the transfer.
 * @param[out]    input_pending Set by the filter that answers.
 * @return The next filter's answer; FALSE (pessimistic) if there is none.
 */
bool Curl_cf_def_conn_is_alive(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *input_pending)
{
  return cf->next ?
    cf->next->cft->is_alive(cf->next, data, input_pending) :
    FALSE; /* pessimistic in absence of data */
}

/**
 * @brief Default keep-alive callback: forward to the next filter.
 * @param[in,out] cf   Filter being used.
 * @param[in,out] data Easy handle of the transfer.
 * @return Result of the next filter, CURLE_OK if there is none.
 */
CURLcode Curl_cf_def_conn_keep_alive(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  return cf->next ?
    cf->next->cft->keep_alive(cf->next, data) :
    CURLE_OK;
}

/**
 * @brief Default query callback: forward the query to the next filter.
 * @param[in,out] cf    Filter being queried.
 * @param[in,out] data  Easy handle of the transfer.
 * @param[in]     query One of the CF_QUERY_* identifiers.
 * @param[out]    pres1 Integer result, meaning depends on @p query.
 * @param[out]    pres2 Pointer result, meaning depends on @p query.
 * @return Result of the next filter, or CURLE_UNKNOWN_OPTION if no filter
 *         in the chain answers the query.
 */
CURLcode Curl_cf_def_query(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int query, int *pres1, void *pres2)
{
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

#ifdef CURLVERBOSE
/**
 * @brief Trace the filter chain of a connection (verbose builds only).
 *
 * Writes a line such as "info [0][TCPv4][TLS]" to the trace; filters
 * that are not yet connected are prefixed with '!'. The output is cut with
 * "..." if it does not fit the internal buffer.
 *
 * @param[in] data      Easy handle used for trace settings.
 * @param[in] sockindex Which chain to print (FIRSTSOCKET/SECONDARYSOCKET).
 * @param[in] info      Text printed before the chain.
 */
void Curl_conn_trc_filters(struct Curl_easy *data,
                           int8_t sockindex, const char *info)
{
  if(CURL_TRC_M_is_verbose(data) && data->conn) {
    struct Curl_cfilter *cf = data->conn->cfilter[sockindex];

    if(cf) {
      char msg[256], *buf;
      int blen, n;

      buf = msg;
      blen = sizeof(msg) - 1;
      n = curl_msnprintf(buf, blen, "%s [%d]", info, sockindex);
      buf += n;
      blen -= n;
      for(; cf && blen; cf = cf->next) {
        n = curl_msnprintf(buf, blen, "[%s%s]",
                           cf->connected ? "" : "!", cf->cft->name);
        buf += n;
        blen -= n;
      }
      CURL_TRC_M(data, "%s%s", msg, blen ? "" : "...");
    }
    else
      CURL_TRC_M(data, "%s [%d][-]", info, sockindex);
  }
}
#endif /* CURLVERBOSE */

/**
 * @brief Destroy and free a filter and all filters below it.
 *
 * Each filter is detached from its sub-chain before its destroy callback
 * runs, so destroy handlers never touch the rest of the chain.
 *
 * @param[in,out] pcf  Pointer to the chain head; set to NULL.
 * @param[in,out] data Easy handle passed to the destroy callbacks.
 * @warning Does not unlink the filter from a connection. Use
 *          Curl_conn_cf_discard() for that.
 * @post *pcf is NULL and all filters are freed.
 */
void Curl_conn_cf_discard_chain(struct Curl_cfilter **pcf,
                                struct Curl_easy *data)
{
  struct Curl_cfilter *cfn, *cf = *pcf;

  if(cf) {
    *pcf = NULL;
    while(cf) {
      cfn = cf->next;
      /* prevent destroying filter to mess with its sub-chain, since
       * we have the reference now and will call destroy on it.
       */
      cf->next = NULL;
      cf->cft->destroy(cf, data);
      curlx_free(cf);
      cf = cfn;
    }
  }
}

/**
 * @brief Discard the whole filter chain of a connection socket index.
 * @param[in,out] data      Easy handle passed to the destroy callbacks.
 * @param[in,out] conn      Connection owning the chain.
 * @param[in]     sockindex Chain to discard.
 * @post Connect and shutdown start times are reset to -1 and the chain is
 *       empty.
 */
void Curl_conn_cf_discard_all(struct Curl_easy *data,
                              struct connectdata *conn, int8_t sockindex)
{
  conn->connect_start_ms = -1;
  conn->shutdown.start_ms[sockindex] = -1;
  Curl_conn_cf_discard_chain(&conn->cfilter[sockindex], data);
}

/**
 * @brief Receive data via the first connected filter of a chain.
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Chain to use.
 * @param[out]    buf       Buffer to receive data.
 * @param[in]     len       Size of @p buf in bytes.
 * @param[out]    pnread    Number of bytes read.
 * @return The result of the filter's receive callback, or
 *         CURLE_FAILED_INIT (with *pnread 0) if no filter is connected.
 * @note Skips unconnected filters at the top of the chain.
 */
CURLcode Curl_cf_recv(struct Curl_easy *data, int8_t sockindex, char *buf,
                      size_t len, size_t *pnread)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[sockindex];
  while(cf && !cf->connected)
    cf = cf->next;
  if(cf)
    return cf->cft->do_recv(cf, data, buf, len, pnread);
  failf(data, "recv: no filter connected");
  DEBUGASSERT(0);
  *pnread = 0;
  return CURLE_FAILED_INIT;
}

/**
 * @brief Send data via the first connected filter of a chain.
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Chain to use.
 * @param[in]     buf       Data to send.
 * @param[in]     len       Number of bytes in @p buf.
 * @param[in]     eos       TRUE if this is the end of the stream.
 * @param[out]    pnwritten Number of bytes accepted.
 * @return The result of the filter's send callback, or
 *         CURLE_FAILED_INIT (with *pnwritten 0) if no filter is connected.
 */
CURLcode Curl_cf_send(struct Curl_easy *data, int8_t sockindex,
                      const uint8_t *buf, size_t len, bool eos,
                      size_t *pnwritten)
{
  struct Curl_cfilter *cf;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  cf = data->conn->cfilter[sockindex];
  while(cf && !cf->connected)
    cf = cf->next;
  if(cf) {
    return cf->cft->do_send(cf, data, buf, len, eos, pnwritten);
  }
  failf(data, "send: no filter connected");
  DEBUGASSERT(0);
  *pnwritten = 0;
  return CURLE_FAILED_INIT;
}

/**
 * @brief Context passed to the bufq reader/writer callbacks.
 * @internal
 *
 * Holds the transfer (data) and the filter (cf) through which buffered
 * I/O is performed.
 */
struct cf_io_ctx {
  struct Curl_easy *data;
  struct Curl_cfilter *cf;
};

/**
 * @brief bufq reader callback: receive from a filter into the queue.
 * @internal
 * @param[in]  writer_ctx Pointer to a struct cf_io_ctx.
 * @param[out] buf        Destination buffer provided by the bufq.
 * @param[in]  blen       Size of @p buf.
 * @param[out] pnread     Number of bytes read.
 * @return Result of Curl_conn_cf_recv().
 */
static CURLcode cf_bufq_reader(void *writer_ctx,
                               unsigned char *buf, size_t blen,
                               size_t *pnread)
{
  struct cf_io_ctx *io = writer_ctx;
  return Curl_conn_cf_recv(io->cf, io->data, (char *)buf, blen, pnread);
}

/**
 * @brief Fill a buffer queue with data read from a filter.
 * @param[in,out] cf     Filter to read from.
 * @param[in,out] data   Easy handle of the transfer.
 * @param[in,out] bufq   Queue receiving the data.
 * @param[in]     maxlen Maximum number of bytes to read (0 for no limit).
 * @param[out]    pnread Number of bytes added to @p bufq.
 * @return CURLE_OK on success, CURLE_BAD_FUNCTION_ARGUMENT if @p cf or
 *         @p data is NULL, otherwise the error from the filter or bufq
 *         (e.g. CURLE_AGAIN when nothing can be read now).
 */
CURLcode Curl_cf_recv_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           size_t maxlen,
                           size_t *pnread)
{
  struct cf_io_ctx io;

  if(!cf || !data) {
    *pnread = 0;
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  io.data = data;
  io.cf = cf;
  return Curl_bufq_sipn(bufq, maxlen, cf_bufq_reader, &io, pnread);
}

/**
 * @brief bufq writer callback: send queue data through a filter.
 * @internal
 * @param[in]  writer_ctx Pointer to a struct cf_io_ctx.
 * @param[in]  buf        Data provided by the bufq.
 * @param[in]  buflen     Number of bytes in @p buf.
 * @param[out] pnwritten  Number of bytes sent.
 * @return Result of Curl_conn_cf_send() (never signals end of stream).
 */
static CURLcode cf_bufq_writer(void *writer_ctx,
                               const uint8_t *buf, size_t buflen,
                               size_t *pnwritten)
{
  struct cf_io_ctx *io = writer_ctx;
  return Curl_conn_cf_send(io->cf, io->data, buf, buflen, FALSE, pnwritten);
}

/**
 * @brief Send data from a buffer queue, optionally adding new data first.
 *
 * If @p buf and @p blen are given, they are appended to the queue and the
 * queue is flushed as far as possible; otherwise only the queue content
 * is passed to the filter.
 *
 * @param[in,out] cf        Filter to send through.
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in,out] bufq      Queue holding pending output.
 * @param[in]     buf       New data to write, may be NULL.
 * @param[in]     blen      Length of @p buf.
 * @param[out]    pnwritten Number of bytes of @p buf that were accepted.
 * @return CURLE_OK on success, CURLE_BAD_FUNCTION_ARGUMENT if @p cf or
 *         @p data is NULL, otherwise the error from the filter or bufq.
 */
CURLcode Curl_cf_send_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           const unsigned char *buf, size_t blen,
                           size_t *pnwritten)
{
  struct cf_io_ctx io;

  if(!cf || !data) {
    *pnwritten = 0;
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  io.data = data;
  io.cf = cf;
  if(buf && blen)
    return Curl_bufq_write_pass(bufq, buf, blen, cf_bufq_writer, &io,
                                pnwritten);
  else
    return Curl_bufq_pass(bufq, cf_bufq_writer, &io, pnwritten);
}

/**
 * @brief Allocate a new filter instance.
 * @param[out] pcf Receives the new filter (NULL on failure).
 * @param[in]  cft Filter type with its callbacks, must not be NULL.
 * @param[in]  ctx Filter-private context stored in cf->ctx.
 * @return CURLE_OK on success, CURLE_OUT_OF_MEMORY if allocation failed.
 * @warning Ownership of @p ctx passes to the filter, which releases it in
 *          its destroy callback.
 * @see Curl_conn_cf_add(), Curl_conn_cf_insert_after()
 */
CURLcode Curl_cf_create(struct Curl_cfilter **pcf,
                        const struct Curl_cftype *cft,
                        void *ctx)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(cft);
  cf = curlx_calloc(1, sizeof(*cf));
  if(!cf)
    goto out;

  cf->cft = cft;
  cf->ctx = ctx;
  result = CURLE_OK;
out:
  *pcf = cf;
  return result;
}

/**
 * @brief Push a filter on top of a connection's filter chain.
 * @param[in,out] data      Easy handle used for tracing.
 * @param[in,out] conn      Connection to add to.
 * @param[in]     sockindex Which chain to add to.
 * @param[in,out] cf        Filter to add; must not be in a chain yet.
 * @post @p cf is the head of the chain and linked to the old head.
 */
void Curl_conn_cf_add(struct Curl_easy *data,
                      struct connectdata *conn,
                      int8_t sockindex,
                      struct Curl_cfilter *cf)
{
  DEBUGASSERT(conn);
  DEBUGASSERT(!cf->conn);
  DEBUGASSERT(!cf->next);

  cf->next = conn->cfilter[sockindex];
  cf->conn = conn;
  cf->sockindex = sockindex;
  conn->cfilter[sockindex] = cf;
  CURL_TRC_CF(data, cf, "added");
}

/**
 * @brief Insert a filter (or sub-chain) behind an existing filter.
 *
 * All inserted filters get the connection and socket index of @p cf_at.
 *
 * @param[in,out] cf_at  Existing filter in a chain.
 * @param[in,out] cf_new Filter or chain to insert; must not be attached to
 *                       a connection yet.
 * @post The old successor of @p cf_at follows the last new filter.
 */
void Curl_conn_cf_insert_after(struct Curl_cfilter *cf_at,
                               struct Curl_cfilter *cf_new)
{
  struct Curl_cfilter *tail, **pnext;

  DEBUGASSERT(cf_at);
  DEBUGASSERT(cf_new);
  DEBUGASSERT(!cf_new->conn);

  tail = cf_at->next;
  cf_at->next = cf_new;
  do {
    cf_new->conn = cf_at->conn;
    cf_new->sockindex = cf_at->sockindex;
    pnext = &cf_new->next;
    cf_new = cf_new->next;
  } while(cf_new);
  *pnext = tail;
}

/**
 * @brief Unlink a filter from its connection and destroy it.
 *
 * If the filter is part of a connection chain it is first removed from
 * that chain; then the filter and everything below it are destroyed.
 *
 * @param[in,out] pcf  Pointer to the filter; set to NULL.
 * @param[in,out] data Easy handle passed to the destroy callbacks.
 * @return TRUE if the filter was found and unlinked from the chain of its
 *         connection, FALSE otherwise.
 */
bool Curl_conn_cf_discard(struct Curl_cfilter **pcf,
                          struct Curl_easy *data)
{
  struct Curl_cfilter *cf = pcf ? *pcf : NULL;
  bool found = FALSE;
  if(cf) {
    if(cf->conn) {
      /* unlink if present in connection filter chain */
      struct Curl_cfilter **pprev = &cf->conn->cfilter[cf->sockindex];
      while(*pprev) {
        if(*pprev == *pcf) {
          *pprev = (*pcf)->next;
          cf->next = NULL;
          found = TRUE;
          break;
        }
        pprev = &(*pprev)->next;
      }
    }
    Curl_conn_cf_discard_chain(pcf, data);
  }
  return found;
}

/**
 * @brief Run the connect step of a filter.
 * @param[in,out] cf   Filter to connect, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @param[out]    done Set TRUE when connected.
 * @return CURLE_OK, an error from the filter, or CURLE_FAILED_INIT if
 *         @p cf is NULL.
 */
CURLcode Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  if(cf)
    return cf->cft->do_connect(cf, data, done);
  return CURLE_FAILED_INIT;
}

/**
 * @brief Send data through a specific filter.
 * @param[in,out] cf        Filter to use, may be NULL.
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in]     buf       Data to send.
 * @param[in]     len       Number of bytes in @p buf.
 * @param[in]     eos       TRUE if this is the end of the stream.
 * @param[out]    pnwritten Number of bytes accepted.
 * @return The filter's result, or CURLE_SEND_ERROR (with *pnwritten 0)
 *         if @p cf is NULL.
 */
CURLcode Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const uint8_t *buf, size_t len, bool eos,
                           size_t *pnwritten)
{
  if(cf)
    return cf->cft->do_send(cf, data, buf, len, eos, pnwritten);
  *pnwritten = 0;
  return CURLE_SEND_ERROR;
}

/**
 * @brief Receive data through a specific filter.
 * @param[in,out] cf     Filter to use, may be NULL.
 * @param[in,out] data   Easy handle of the transfer.
 * @param[out]    buf    Buffer to receive data.
 * @param[in]     len    Size of @p buf in bytes.
 * @param[out]    pnread Number of bytes read.
 * @return The filter's result, or CURLE_RECV_ERROR (with *pnread 0) if
 *         @p cf is NULL.
 */
CURLcode Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, size_t *pnread)
{
  if(cf)
    return cf->cft->do_recv(cf, data, buf, len, pnread);
  *pnread = 0;
  return CURLE_RECV_ERROR;
}

/**
 * @brief Send a control event to all filter chains of a connection.
 * @internal
 * @param[in,out] conn          Connection whose chains are visited.
 * @param[in,out] data          Easy handle of the transfer.
 * @param[in]     ignore_result TRUE to continue past filter errors.
 * @param[in]     event         CF_CTRL_* event.
 * @param[in]     arg1          Event-specific integer argument.
 * @param[in,out] arg2          Event-specific pointer argument.
 * @return CURLE_OK, or the first error if @p ignore_result is FALSE,
 *         otherwise the result of the last chain visited.
 */
static CURLcode cf_cntrl_all(struct connectdata *conn,
                             struct Curl_easy *data,
                             bool ignore_result,
                             int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;
  int i;

  for(i = 0; i < (int)CURL_ARRAYSIZE(conn->cfilter); ++i) {
    result = Curl_conn_cf_cntrl(conn->cfilter[i], data, ignore_result,
                                event, arg1, arg2);
    if(!ignore_result && result)
      break;
  }
  return result;
}

/**
 * @brief Check if the IP level connection of a filter chain is up.
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return TRUE if the CF_QUERY_REALLY_CONNECTED query succeeded and
 *         reported connected, FALSE otherwise.
 */
bool Curl_conn_cf_is_ip_connected(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  if(cf) {
    int value = 0;
    if(!cf->cft->query(cf, data, CF_QUERY_REALLY_CONNECTED, &value, NULL))
      return !!value;
  }
  return FALSE;
}

/**
 * @brief Ask all filters to update the transfer's connection info.
 * @param[in,out] data Easy handle of the transfer.
 * @param[in,out] conn Connection to notify.
 * @note Errors from filters are ignored.
 */
void Curl_conn_cntrl_update_info(struct Curl_easy *data,
                                struct connectdata *conn)
{
  cf_cntrl_all(conn, data, TRUE, CF_CTRL_CONN_INFO_UPDATE, 0, NULL);
}

/**
 * @brief Ask the filters of one chain to report their statistics.
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in,out] conn      Connection to notify.
 * @param[in]     sockindex Chain index; out of range values are ignored.
 */
void Curl_conn_cntrl_report_stats(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex)
{
  if((unsigned)sockindex < CURL_ARRAYSIZE(conn->cfilter))
    (void)Curl_conn_cf_cntrl(conn->cfilter[sockindex], data, TRUE,
                             CF_CTRL_REPORT_STATS, 0, NULL);
}

/**
 * @brief Remove connected "setup" filters from a chain.
 *
 * Filters of type CF_TYPE_SETUP only drive connection establishment. Once
 * connected they are unlinked and destroyed.
 *
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Chain to clean up.
 */
void Curl_conn_remove_setup_filters(struct Curl_easy *data,
                                    int8_t sockindex)
{
  struct Curl_cfilter **anchor = &data->conn->cfilter[sockindex];
  while(*anchor) {
    struct Curl_cfilter *cf = *anchor;
    if(cf->connected && (cf->cft->flags & CF_TYPE_SETUP)) {
      *anchor = cf->next;
      cf->next = NULL;
      CURL_TRC_CF(data, cf, "removing connected setup filter");
      cf->cft->destroy(cf, data);
      curlx_free(cf);
    }
    else
      anchor = &cf->next;
  }
}

/**
 * @brief Check if a filter chain exists for a socket index.
 * @param[in] conn      Connection to inspect.
 * @param[in] sockindex Chain index.
 * @return TRUE if the chain has at least one filter, FALSE if empty or the
 *         index is invalid.
 */
bool Curl_conn_is_setup(struct connectdata *conn, int8_t sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return !!conn->cfilter[sockindex];
}

/**
 * @brief Check if a connection socket index is fully connected.
 * @param[in] conn      Connection to inspect.
 * @param[in] sockindex Chain index.
 * @return TRUE if the top filter is connected, or if the chain is empty
 *         and the scheme needs no network (PROTOPT_NONETWORK). FALSE
 *         otherwise, including for an invalid index.
 */
bool Curl_conn_is_connected(struct connectdata *conn, int8_t sockindex)
{
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  cf = conn->cfilter[sockindex];
  if(cf)
    return (bool)cf->connected;
  else if(conn->scheme->flags & PROTOPT_NONETWORK)
    return TRUE;
  return FALSE;
}

/**
 * @brief Check if the IP connection (below TLS etc.) is established.
 *
 * Walks down the chain from the top: connected filters answer TRUE, the
 * first filter of type CF_TYPE_IP_CONNECT stops the search with FALSE.
 *
 * @param[in] data      Easy handle with an attached connection.
 * @param[in] sockindex Chain index.
 * @return TRUE if a connected filter is found above the IP layer filter,
 *         FALSE otherwise.
 */
bool Curl_conn_is_ip_connected(struct Curl_easy *data, int8_t sockindex)
{
  struct Curl_cfilter *cf;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  cf = data->conn->cfilter[sockindex];
  while(cf) {
    if(cf->connected)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
    cf = cf->next;
  }
  return FALSE;
}

#ifndef CURL_DISABLE_PROXY
/**
 * @brief Check if a chain contains a tunneling proxy filter.
 * @internal
 * @param[in] cf Top of the (sub-)chain.
 * @return TRUE if any filter has CF_TYPE_PROXY set.
 */
static bool cf_is_tunneling(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if((cf->cft->flags & CF_TYPE_PROXY))
      return TRUE;
  }
  return FALSE;
}

/**
 * @brief Check if the connection is tunneled through a proxy.
 * @param[in] conn      Connection to inspect, may be NULL.
 * @param[in] sockindex Chain index.
 * @return TRUE if a proxy tunnel filter is in the chain, FALSE otherwise
 *         (also for an invalid index or NULL connection).
 */
bool Curl_conn_is_tunneling(struct connectdata *conn, int8_t sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return conn ? cf_is_tunneling(conn->cfilter[sockindex]) : FALSE;
}
#else
/**
 * @brief Stub when proxy support is disabled: never tunneling.
 * @param[in] conn      Unused.
 * @param[in] sockindex Unused.
 * @return Always FALSE.
 */
bool Curl_conn_is_tunneling(struct connectdata *conn, int8_t sockindex)
{
  (void)conn;
  (void)sockindex;
  return FALSE;
}
#endif /* CURL_DISABLE_PROXY */

/**
 * @brief Check if a chain provides end-to-end TLS.
 * @internal
 *
 * Scans down to the IP connect filter. A TLS filter that belongs to a
 * proxy does not count, as a tunneling proxy does not offer end-to-end
 * encryption even if it uses TLS itself (e.g. QUIC H3 proxy).
 *
 * @param[in] cf Top of the chain.
 * @return TRUE if a non-proxy CF_TYPE_SSL filter is found above the IP
 *         connect filter, FALSE otherwise.
 */
static bool cf_is_ssl(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    /* A tunneling proxy does not offer end2end encryption, even if
     * it does SSL itself (e.g. QUIC H3 proxy) */
    if((cf->cft->flags & CF_TYPE_SSL) && !(cf->cft->flags & CF_TYPE_PROXY))
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

/**
 * @brief Check if a connection uses end-to-end TLS.
 * @param[in] conn      Connection to inspect, may be NULL.
 * @param[in] sockindex Chain index.
 * @return TRUE if the chain is TLS protected, FALSE otherwise.
 */
bool Curl_conn_is_ssl(struct connectdata *conn, int8_t sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return conn ? cf_is_ssl(conn->cfilter[sockindex]) : FALSE;
}

/**
 * @brief Query TLS session information from the filter chain.
 * @param[in]  data      Easy handle of the transfer.
 * @param[in]  conn      Connection to inspect.
 * @param[in]  sockindex Chain index.
 * @param[in]  query     Query identifier passed to the filter.
 * @param[out] info      Receives the TLS session info.
 * @return TRUE if the connection uses TLS and the filter answered the
 *         query, FALSE otherwise.
 */
bool Curl_conn_get_ssl_info(struct Curl_easy *data,
                            struct connectdata *conn, int8_t sockindex,
                            int query,
                            struct curl_tlssessioninfo *info)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  if(Curl_conn_is_ssl(conn, sockindex)) {
    struct Curl_cfilter *cf = conn->cfilter[sockindex];
    CURLcode result = cf ?
      cf->cft->query(cf, data, query, NULL, (void *)info) :
      CURLE_UNKNOWN_OPTION;
    return !result;
  }
  return FALSE;
}

/**
 * @brief Get IP address information of a connection.
 * @param[in]  data      Easy handle of the transfer.
 * @param[in]  conn      Connection to inspect, may be NULL.
 * @param[in]  sockindex Chain index.
 * @param[out] is_ipv6   TRUE if the connection uses IPv6.
 * @param[out] ipquad    Local/remote address and port.
 * @return CURLE_OK on success, CURLE_BAD_FUNCTION_ARGUMENT for an invalid
 *         index, CURLE_UNKNOWN_OPTION if no filter answers.
 * @see Curl_conn_cf_get_ip_info()
 */
CURLcode Curl_conn_get_ip_info(struct Curl_easy *data,
                               struct connectdata *conn, int8_t sockindex,
                               bool *is_ipv6, struct ip_quadruple *ipquad)
{
  struct Curl_cfilter *cf;
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  cf = conn ? conn->cfilter[sockindex] : NULL;
  return Curl_conn_cf_get_ip_info(cf, data, is_ipv6, ipquad);
}

/**
 * @brief Check if the connection can multiplex transfers.
 * @param[in] conn      Connection to inspect, may be NULL.
 * @param[in] sockindex Chain index.
 * @return TRUE if a CF_TYPE_MULTIPLEX filter is found above the IP and
 *         TLS filters, FALSE otherwise.
 */
bool Curl_conn_is_multiplex(struct connectdata *conn, int8_t sockindex)
{
  struct Curl_cfilter *cf;

  if(!conn || !CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  for(cf = conn->cfilter[sockindex]; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_MULTIPLEX)
      return TRUE;
    if(cf->cft->flags & (CF_TYPE_IP_CONNECT | CF_TYPE_SSL))
      return FALSE;
  }
  return FALSE;
}

/**
 * @brief Get the transport (TCP, UDP, QUIC, UNIX) of a connection.
 * @param[in] data Easy handle of the transfer.
 * @param[in] conn Connection to inspect.
 * @return One of the TRNSPRT_* values from the first socket's chain.
 * @see Curl_conn_cf_get_transport()
 */
unsigned char Curl_conn_get_transport(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  return Curl_conn_cf_get_transport(cf, data);
}

/**
 * @brief Map a transport to a socket type.
 * @param[in] transport TRNSPRT_* value.
 * @return SOCK_STREAM for TCP and UNIX, SOCK_DGRAM otherwise.
 */
int Curl_socktype_for_transport(uint8_t transport)
{
  switch(transport) {
  case TRNSPRT_TCP:
    return SOCK_STREAM;
  case TRNSPRT_UNIX:
    return SOCK_STREAM;
  default: /* UDP and QUIC */
    return SOCK_DGRAM;
  }
}

/**
 * @brief Map a transport to an IP protocol number.
 * @param[in] transport TRNSPRT_* value.
 * @return IPPROTO_TCP for TCP, IPPROTO_IP for UNIX, IPPROTO_UDP otherwise.
 */
int Curl_protocol_for_transport(uint8_t transport)
{
  switch(transport) {
  case TRNSPRT_TCP:
    return IPPROTO_TCP;
  case TRNSPRT_UNIX:
    return IPPROTO_IP;
  default: /* UDP and QUIC */
    return IPPROTO_UDP;
  }
}

/**
 * @brief Determine the HTTP version negotiated on a filter chain.
 *
 * Looks for a CF_TYPE_HTTP filter above the IP connect and TLS filters
 * and queries it with CF_QUERY_HTTP_VERSION.
 *
 * @param[in] data Easy handle of the transfer.
 * @param[in] cf   Top of the chain to inspect.
 * @return The version as reported by the filter, or 0 if unknown, the
 *         query failed or the value is out of range.
 */
uint8_t Curl_conn_cf_http_version(struct Curl_easy *data,
                                  struct Curl_cfilter *cf)
{
  CURLcode result = CURLE_UNKNOWN_OPTION;
  uint8_t v = 0;

  for(; cf; cf = cf->next) {
    if(cf->cft->flags & CF_TYPE_HTTP) {
      int value = 0;
      result = cf->cft->query(cf, data, CF_QUERY_HTTP_VERSION, &value, NULL);
      if(!result && ((value < 0) || (value > 255)))
        result = CURLE_FAILED_INIT;
      else
        v = (uint8_t)value;
      break;
    }
    if(cf->cft->flags & (CF_TYPE_IP_CONNECT | CF_TYPE_SSL))
      break;
  }
  return (uint8_t)(result ? 0 : v);
}

/**
 * @brief Determine the HTTP version used on the first socket.
 * @param[in] data Easy handle of the transfer.
 * @param[in] conn Connection to inspect.
 * @return HTTP version, 0 if unknown.
 * @see Curl_conn_cf_http_version()
 */
uint8_t Curl_conn_http_version(struct Curl_easy *data,
                               struct connectdata *conn)
{
  return Curl_conn_cf_http_version(data, conn->cfilter[FIRSTSOCKET]);
}

/**
 * @brief Check if buffered data can be read without further socket I/O.
 * @param[in] data      Easy handle with an attached connection.
 * @param[in] sockindex Chain index.
 * @return TRUE if the first connected filter reports pending data, FALSE
 *         otherwise.
 */
bool Curl_conn_data_pending(struct Curl_easy *data, int8_t sockindex)
{
  struct Curl_cfilter *cf;

  (void)data;
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;

  cf = data->conn->cfilter[sockindex];
  while(cf && !cf->connected) {
    cf = cf->next;
  }
  if(cf) {
    return cf->cft->has_data_pending(cf, data);
  }
  return FALSE;
}

/**
 * @brief Check if a filter chain has output that still needs flushing.
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return TRUE if CF_QUERY_NEED_FLUSH succeeded and reported pending
 *         output, FALSE otherwise.
 */
bool Curl_conn_cf_needs_flush(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  CURLcode result;
  int pending = 0;
  result = cf ? cf->cft->query(cf, data, CF_QUERY_NEED_FLUSH,
                               &pending, NULL) : CURLE_UNKNOWN_OPTION;
  return (result || !pending) ? FALSE : TRUE;
}

/**
 * @brief Check if the chain of a socket index needs flushing.
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Chain index.
 * @return TRUE if output is pending, FALSE if not or on invalid index.
 */
bool Curl_conn_needs_flush(struct Curl_easy *data, int8_t sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return FALSE;
  return Curl_conn_cf_needs_flush(data->conn->cfilter[sockindex], data);
}

/**
 * @brief Let the filters of a chain add their sockets to a pollset.
 * @param[in,out] cf   Top of the chain.
 * @param[in,out] data Easy handle of the transfer.
 * @param[in,out] ps   Pollset to adjust.
 * @return CURLE_OK, or the first error from a filter's adjust_pollset.
 * @note Filters in shutdown are skipped.
 */
CURLcode Curl_conn_cf_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;
  /* Go through all filters, top to bottom, and let them manage the pollset
   * - connected filters can do so
   * - CF_TYPE_DNS filters can
   * - unconnected filters without next or connect next can
   */
  for(; cf && !result; cf = cf->next) {
    if(cf->shutdown)
      continue;
    if(cf->connected || (cf->cft->flags & CF_TYPE_DNS) ||
       !cf->next || cf->next->connected)
      result = cf->cft->adjust_pollset(cf, data, ps);
  }
  return result;
}

/**
 * @brief Let the connection's filter chains update the transfer pollset.
 *
 * @param[in,out] data Easy handle of the transfer.
 * @param[in,out] conn Connection whose chains are visited.
 * @param[in,out] ps   Pollset to adjust.
 * @return CURLE_OK or the first error from a chain.
 * @note A chain is only consulted if the transfer wants I/O, the chain is
 *       not connected yet or it is in shutdown (see inline comment).
 */
CURLcode Curl_conn_adjust_pollset(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  struct easy_pollset *ps)
{
  CURLcode result = CURLE_OK;
  const bool want_io = !!ps->n;
  int8_t i;

  DEBUGASSERT(data);
  DEBUGASSERT(conn);
  /* During connect time, connection filters may add sockets to the pollset
   * even when the transfer neither wants to send nor receive. And those
   * sockets, when having events, are served. The same applies to a
   * filter chain whose shutdown has started.
   * Once a filter chain is connected however and before its shutdown
   * starts, a transfer that neither wants to send nor receive
   * will never call the connection filters. Any sockets added by the filters
   * will not change state and POLLIN/POLLOUT events will trigger forever,
   * making us busy loop. See #21671.
   * Gate each filter chain on its own state, so that one chain being in
   * connect or shutdown does not add poll events for the other. Check
   * against the transfer's own interest, before any chain added sockets
   * of its own. */
  for(i = 0; (i < (int)CURL_ARRAYSIZE(conn->cfilter)) && !result; ++i) {
    if(conn->cfilter[i] &&
       (want_io || !conn->cfilter[i]->connected ||
        CURL_CONN_IN_SHUTDOWN(conn, i)))
      result = Curl_conn_cf_adjust_pollset(conn->cfilter[i], data, ps);
  }
  return result;
}

/**
 * @brief Poll the sockets a filter chain is interested in.
 * @param[in,out] cf         Top of the chain, must not be NULL.
 * @param[in,out] data       Easy handle with an attached connection.
 * @param[in]     timeout_ms Maximum time to wait in milliseconds.
 * @return -1 on error, 0 on timeout, otherwise the number of structures
 *         with non zero revent fields.
 */
int Curl_conn_cf_poll(struct Curl_cfilter *cf,
                      struct Curl_easy *data,
                      timediff_t timeout_ms)
{
  struct easy_pollset ps;
  int rc;
  CURLcode result;

  DEBUGASSERT(cf);
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  Curl_pollset_init(&ps);

  result = Curl_conn_cf_adjust_pollset(cf, data, &ps);
  if(!result)
    rc = Curl_pollset_poll(data, &ps, timeout_ms);
  else
    rc = -1;
  Curl_pollset_cleanup(&ps);
  return rc;
}

/**
 * @brief Get the host and port currently being talked to.
 *
 * While a tunneling proxy filter has not connected yet, the interim host
 * is the proxy; otherwise it is the destination of the connection.
 *
 * @param[in]  data      Easy handle of the transfer.
 * @param[in]  sockindex Chain index.
 * @param[out] phost     Receives the hostname (not owned by caller).
 * @param[out] pport     Receives the port, may be NULL.
 * @warning The returned string points into connection or filter data and
 *          is only valid as long as those live.
 */
void Curl_conn_get_current_host(struct Curl_easy *data, int8_t sockindex,
                                const char **phost, int *pport)
{
  struct Curl_cfilter *cf, *cf_proxy = NULL;
  int portarg = -1;

  if(!data->conn) {
    DEBUGASSERT(0);
    *phost = "";
    if(pport)
      *pport = -1;
    return;
  }

  cf = CONN_SOCK_IDX_VALID(sockindex) ? data->conn->cfilter[sockindex] : NULL;
  /* Find the "lowest" tunneling proxy filter that has not connected yet. */
  while(cf && !cf->connected) {
    if((cf->cft->flags & (CF_TYPE_IP_CONNECT | CF_TYPE_PROXY)) ==
       (CF_TYPE_IP_CONNECT | CF_TYPE_PROXY))
      cf_proxy = cf;
    cf = cf->next;
  }
  /* cf_proxy (!= NULL) is not connected yet. It is talking
   * to an interim host and any authentication or other things apply
   * to this interim host and port. */
  if(!cf_proxy || cf_proxy->cft->query(cf_proxy, data, CF_QUERY_HOST_PORT,
                                       &portarg, CURL_UNCONST(phost))) {
    /* Everything connected or query unsuccessful, the overall
     * connection's destination is the answer */
    *phost = data->conn->origin->hostname;
    portarg = data->conn->origin->port;
  }
  if(pport)
    *pport = portarg;
}

/**
 * @brief Default control callback: ignore the event.
 * @param[in,out] cf    Filter (unused).
 * @param[in,out] data  Easy handle (unused).
 * @param[in]     event CF_CTRL_* event (unused).
 * @param[in]     arg1  Event argument (unused).
 * @param[in,out] arg2  Event argument (unused).
 * @return Always CURLE_OK.
 */
CURLcode Curl_cf_def_cntrl(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int event, int arg1, void *arg2)
{
  (void)cf;
  (void)data;
  (void)event;
  (void)arg1;
  (void)arg2;
  return CURLE_OK;
}

/**
 * @brief Send a control event to a filter and all filters below it.
 *
 * Filters that use the default control handler are skipped.
 *
 * @param[in,out] cf            Top of the chain, may be NULL.
 * @param[in,out] data          Easy handle of the transfer.
 * @param[in]     ignore_result TRUE to continue past errors.
 * @param[in]     event         CF_CTRL_* event.
 * @param[in]     arg1          Event-specific integer argument.
 * @param[in,out] arg2          Event-specific pointer argument.
 * @return CURLE_OK, or the first error if @p ignore_result is FALSE,
 *         otherwise the result of the last handler.
 */
CURLcode Curl_conn_cf_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            bool ignore_result,
                            int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;

  for(; cf; cf = cf->next) {
    if(cf->cft->cntrl == Curl_cf_def_cntrl)
      continue;
    result = cf->cft->cntrl(cf, data, event, arg1, arg2);
    if(!ignore_result && result)
      break;
  }
  return result;
}

/**
 * @brief Get the socket of a filter chain.
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return The socket, or CURL_SOCKET_BAD if the query fails.
 */
curl_socket_t Curl_conn_cf_get_socket(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  curl_socket_t sock;
  if(cf && !cf->cft->query(cf, data, CF_QUERY_SOCKET, NULL, &sock))
    return sock;
  return CURL_SOCKET_BAD;
}

/**
 * @brief Get the transport used by a filter chain.
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return The TRNSPRT_* value reported by the chain, otherwise the
 *         transport wanted by the connection (0 if no connection).
 */
unsigned char Curl_conn_cf_get_transport(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  int transport = 0;
  if(cf && !cf->cft->query(cf, data, CF_QUERY_TRANSPORT, &transport, NULL))
    return (unsigned char)transport;
  return (unsigned char)(data->conn ? data->conn->transport_wanted : 0);
}

/**
 * @brief Get the ALPN protocol negotiated on a filter chain.
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return The ALPN identifier, or NULL if none was negotiated.
 * @warning The string is owned by the filter; do not free it.
 */
const char *Curl_conn_cf_get_alpn_negotiated(struct Curl_cfilter *cf,
                                             struct Curl_easy *data)
{
  const char *alpn = NULL;
  CURL_TRC_CF(data, cf, "query ALPN");
  if(cf && !cf->cft->query(cf, data, CF_QUERY_ALPN_NEGOTIATED, NULL,
                           CURL_UNCONST(&alpn)))
    return alpn;
  return NULL;
}

/**
 * @brief Query the remote address of a filter chain.
 * @internal
 * @param[in,out] cf   Filter to ask, may be NULL.
 * @param[in,out] data Easy handle of the transfer.
 * @return The remote address, or NULL if the query failed.
 * @warning The address is owned by the filter chain.
 */
static const struct Curl_sockaddr_ex *cf_get_remote_addr(
  struct Curl_cfilter *cf, struct Curl_easy *data)
{
  const struct Curl_sockaddr_ex *remote_addr = NULL;
  if(cf &&
     !cf->cft->query(cf, data, CF_QUERY_REMOTE_ADDR, NULL,
                     CURL_UNCONST(&remote_addr)))
    return remote_addr;
  return NULL;
}

/**
 * @brief Get IP address information from a filter chain.
 * @param[in,out] cf      Filter to ask, may be NULL.
 * @param[in,out] data    Easy handle of the transfer.
 * @param[out]    is_ipv6 TRUE if IPv6 is used (only set if @p cf given).
 * @param[out]    ipquad  Receives the address quadruple.
 * @return CURLE_OK on success, CURLE_UNKNOWN_OPTION if @p cf is NULL or
 *         does not answer.
 */
CURLcode Curl_conn_cf_get_ip_info(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *is_ipv6, struct ip_quadruple *ipquad)
{
  CURLcode result = CURLE_UNKNOWN_OPTION;
  if(cf) {
    int ipv6 = 0;
    result = cf->cft->query(cf, data, CF_QUERY_IP_INFO, &ipv6, ipquad);
    *is_ipv6 = !!ipv6;
  }
  return result;
}

/**
 * @brief Get the primary socket of the connection.
 * @param[in] data Easy handle of the transfer.
 * @return The socket, or CURL_SOCKET_BAD if there is no connection.
 * @note If the top filter is not connected yet, the chain is queried,
 *       otherwise conn->sock[FIRSTSOCKET] is used.
 */
curl_socket_t Curl_conn_get_first_socket(struct Curl_easy *data)
{
  struct Curl_cfilter *cf;

  if(!data->conn)
    return CURL_SOCKET_BAD;

  cf = data->conn->cfilter[FIRSTSOCKET];
  /* if the top filter has not connected, ask it (and its sub-filters)
   * for the socket. Otherwise conn->sock[sockindex] should have it. */
  if(cf && !cf->connected)
    return Curl_conn_cf_get_socket(cf, data);
  return data->conn->sock[FIRSTSOCKET];
}

/**
 * @brief Get the remote address of a connection socket index.
 * @param[in] data      Easy handle of the transfer.
 * @param[in] sockindex Chain index.
 * @return The remote address, or NULL if unavailable.
 * @warning The address is owned by the filter chain.
 */
const struct Curl_sockaddr_ex *Curl_conn_get_remote_addr(
  struct Curl_easy *data, int8_t sockindex)
{
  struct Curl_cfilter *cf =
    (data->conn && CONN_SOCK_IDX_VALID(sockindex)) ?
    data->conn->cfilter[sockindex] : NULL;
  return cf ? cf_get_remote_addr(cf, data) : NULL;
}

/**
 * @brief Notify filters that a transfer is set up on the connection.
 * @param[in,out] data Easy handle of the transfer.
 * @return CURLE_OK or the first error from a filter.
 */
CURLcode Curl_conn_ev_data_setup(struct Curl_easy *data)
{
  return cf_cntrl_all(data->conn, data, FALSE, CF_CTRL_DATA_SETUP, 0, NULL);
}

/**
 * @brief Ask the filters of a socket index to flush pending output.
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Chain index.
 * @return CURLE_OK, CURLE_AGAIN style results from filters, or
 *         CURLE_BAD_FUNCTION_ARGUMENT for an invalid index.
 */
CURLcode Curl_conn_flush(struct Curl_easy *data, int8_t sockindex)
{
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return Curl_conn_cf_cntrl(data->conn->cfilter[sockindex], data, FALSE,
                            CF_CTRL_FLUSH, 0, NULL);
}

/**
 * @brief Notify filters that the transfer is done sending data.
 *
 * For example when it has uploaded everything.
 *
 * @param[in,out] data Easy handle of the transfer.
 * @note Errors from filters are ignored.
 */
void Curl_conn_ev_data_done_send(struct Curl_easy *data)
{
  cf_cntrl_all(data->conn, data, TRUE, CF_CTRL_DATA_DONE_SEND, 0, NULL);
}

/**
 * @brief Notify filters that the transfer is finished.
 *
 * The transfer may end prematurely, e.g. before being complete.
 *
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in]     premature TRUE if the transfer ended before completion.
 * @note Errors from filters are ignored.
 */
void Curl_conn_ev_data_done(struct Curl_easy *data, bool premature)
{
  cf_cntrl_all(data->conn, data, TRUE, CF_CTRL_DATA_DONE, premature, NULL);
}

/**
 * @brief Notify filters that the transfer is paused or unpaused.
 * @param[in,out] data     Easy handle of the transfer.
 * @param[in]     do_pause TRUE to pause, FALSE to resume.
 * @return CURLE_OK or the first error from a filter.
 */
CURLcode Curl_conn_ev_data_pause(struct Curl_easy *data, bool do_pause)
{
  return cf_cntrl_all(data->conn, data, FALSE,
                      CF_CTRL_DATA_PAUSE, do_pause, NULL);
}

/**
 * @brief Check if the first socket's connection is still usable.
 * @param[in,out] data          Easy handle of the transfer.
 * @param[in,out] conn          Connection to check.
 * @param[out]    input_pending Set if unread input is waiting.
 * @return TRUE if a filter exists, the connection is not marked for close
 *         and the filter reports it alive; FALSE otherwise.
 */
bool Curl_conn_is_alive(struct Curl_easy *data, struct connectdata *conn,
                        bool *input_pending)
{
  struct Curl_cfilter *cf = conn->cfilter[FIRSTSOCKET];
  return cf && !cf->conn->bits.close &&
         cf->cft->is_alive(cf, data, input_pending);
}

/**
 * @brief Send keep-alive signals on all chains of a connection.
 * @param[in,out] data Easy handle of the transfer.
 * @param[in,out] conn Connection to use.
 * @return CURLE_OK, or the first error from a filter.
 */
CURLcode Curl_conn_keep_alive(struct Curl_easy *data,
                              struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  int i;

  for(i = 0; (i < (int)CURL_ARRAYSIZE(conn->cfilter)) && !result; ++i) {
    struct Curl_cfilter *cf = conn->cfilter[i];
    if(cf)
      result = cf->cft->keep_alive(cf, data);
  }
  return result;
}

/**
 * @brief Get how many transfers the connection can run in parallel.
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in,out] conn      Connection to query.
 * @param[in]     sockindex Chain index.
 * @return The limit; 1 for non-multiplexed connections or if no filter
 *         answers, 0 for an invalid index. May be 0 for connections in
 *         shutdown, e.g. after a server HTTP/2 GOAWAY.
 */
size_t Curl_conn_get_max_concurrent(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int8_t sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;
  int n = -1;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return 0;

  cf = conn->cfilter[sockindex];
  result = cf ? cf->cft->query(cf, data, CF_QUERY_MAX_CONCURRENT,
                               &n, NULL) : CURLE_UNKNOWN_OPTION;
  /* If no filter answered the query, the default is a non-multiplexed
   * connection with limit 1. Otherwise, the query may return 0
   * for connections that are in shutdown, e.g. server HTTP/2 GOAWAY. */
  return (result || n < 0) ? 1 : (size_t)n;
}

/**
 * @brief Get the stream error code of a connection, if any.
 * @param[in,out] data      Easy handle of the transfer.
 * @param[in,out] conn      Connection to query.
 * @param[in]     sockindex Chain index.
 * @return The protocol specific error code, 0 if none, unknown or on an
 *         invalid index.
 */
int Curl_conn_get_stream_error(struct Curl_easy *data,
                               struct connectdata *conn,
                               int8_t sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;
  int n = 0;

  if(!CONN_SOCK_IDX_VALID(sockindex))
    return 0;

  cf = conn->cfilter[sockindex];
  result = cf ? cf->cft->query(cf, data, CF_QUERY_STREAM_ERROR,
                               &n, NULL) : CURLE_UNKNOWN_OPTION;
  return (result || n < 0) ? 0 : n;
}

/**
 * @brief Map a socket descriptor to its connection socket index.
 * @param[in] data   Easy handle of the transfer, may be NULL.
 * @param[in] sockfd Socket descriptor.
 * @return SECONDARYSOCKET if @p sockfd is the connection's secondary
 *         socket, FIRSTSOCKET otherwise.
 */
int8_t Curl_conn_sockindex(struct Curl_easy *data, curl_socket_t sockfd)
{
  if(data && data->conn &&
     sockfd != CURL_SOCKET_BAD && sockfd == data->conn->sock[SECONDARYSOCKET])
    return SECONDARYSOCKET;
  return FIRSTSOCKET;
}

/**
 * @brief Receive data on a connection via its recv function.
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Socket index.
 * @param[out]    buf       Buffer to receive data.
 * @param[in]     len       Size of @p buf.
 * @param[out]    pnread    Number of bytes read.
 * @return The recv function's result, CURLE_BAD_FUNCTION_ARGUMENT for an
 *         invalid index, CURLE_FAILED_INIT if no recv function is set.
 */
CURLcode Curl_conn_recv(struct Curl_easy *data, int8_t sockindex,
                        char *buf, size_t len, size_t *pnread)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(data && data->conn && data->conn->recv[sockindex])
    return data->conn->recv[sockindex](data, sockindex, buf, len, pnread);
  *pnread = 0;
  return CURLE_FAILED_INIT;
}

/**
 * @brief Send data on a connection via its send function.
 *
 * In debug builds, the CURL_SMALLSENDS environment variable limits the
 * number of bytes sent per call to force short writes.
 *
 * @param[in,out] data      Easy handle with an attached connection.
 * @param[in]     sockindex Socket index.
 * @param[in]     buf       Data to send.
 * @param[in]     len       Number of bytes in @p buf.
 * @param[in]     eos       TRUE if this is the end of the stream.
 * @param[out]    pnwritten Number of bytes accepted.
 * @return The send function's result, CURLE_BAD_FUNCTION_ARGUMENT for an
 *         invalid index, CURLE_SEND_ERROR if more bytes were reported
 *         than offered, CURLE_FAILED_INIT if no send function is set.
 * @note When a short send is forced, @p eos is reset to FALSE.
 */
CURLcode Curl_conn_send(struct Curl_easy *data, int8_t sockindex,
                        const void *buf, size_t len, bool eos,
                        size_t *pnwritten)
{
  size_t write_len = len;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  DEBUGASSERT(CONN_SOCK_IDX_VALID(sockindex));
  if(!CONN_SOCK_IDX_VALID(sockindex))
    return CURLE_BAD_FUNCTION_ARGUMENT;
#ifdef DEBUGBUILD
  if(write_len) {
    /* Allow debug builds to override this logic to force short sends */
    const char *p = getenv("CURL_SMALLSENDS");
    if(p) {
      curl_off_t altsize;
      if(!curlx_str_number(&p, &altsize, write_len)) {
        write_len = (size_t)altsize;
        if(write_len != len)
          eos = FALSE;
      }
    }
  }
#endif
  if(data && data->conn && data->conn->send[sockindex]) {
    CURLcode result = data->conn->send[sockindex](data, sockindex, buf,
                                                  write_len, eos, pnwritten);
    if(!result && (*pnwritten > write_len)) {
      DEBUGASSERT(0);
      *pnwritten = 0;
      return CURLE_SEND_ERROR;
    }
    return result;
  }
  *pnwritten = 0;
  return CURLE_FAILED_INIT;
}
