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
 * @brief Client writer and client reader stacks for transfer data.
 *
 * This file implements the two filter-like stacks that sit between libcurl
 * and the application for one transfer:
 *
 * - The client *writer* stack (data->req.writer) receives downloaded data
 *   (headers, body, informational text) and passes it through ordered phases
 *   (raw, before-decode, content-decode, protocol, client) until it reaches
 *   the application's write callbacks (see cw-out.c).
 * - The client *reader* stack (data->req.reader) produces upload data from
 *   the application's read callback, a memory buffer, or nothing, optionally
 *   converting line endings.
 *
 * Each stack is a singly linked list of instances. An instance is created
 * from a type descriptor (struct Curl_cwtype / struct Curl_crtype) and has
 * a context area allocated together with the instance itself.
 *
 * @see sendf.h, cw-out.h, cw-pause.h
 */

#include "curl_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "curl_trc.h"
#include "transfer.h"
#include "cfilters.h"
#include "connect.h"
#include "cw-out.h"
#include "cw-pause.h"
#include "multiif.h"
#include "progress.h"

/**
 * @brief Close and free all client writers of the transfer.
 * @internal
 *
 * Pops each writer off data->req.writer.stack, calls its do_close() handler
 * and frees it. Also clears the "paused" flag of the writer stack.
 *
 * @param[in,out] data Transfer whose writer stack is emptied.
 * @post data->req.writer.stack == NULL and data->req.writer.paused == FALSE.
 */
static void cl_reset_writer(struct Curl_easy *data)
{
  struct Curl_cwriter *writer = data->req.writer.stack;
  while(writer) {
    data->req.writer.stack = writer->next;
    writer->cwt->do_close(data, writer);
    curlx_free(writer);
    writer = data->req.writer.stack;
  }
  data->req.writer.paused = FALSE;
}

/**
 * @brief Close and free all client readers of the transfer.
 * @internal
 *
 * Pops each reader off data->req.reader.stack, calls its do_close() handler
 * and frees it. Resets the "reader started" marker so the upload rate
 * limiter is restarted on the next read.
 *
 * @param[in,out] data Transfer whose reader stack is emptied.
 * @post data->req.reader.stack == NULL and data->req.reader_started is FALSE.
 */
static void cl_reset_reader(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader.stack;
  data->req.reader_started = FALSE;
  while(reader) {
    data->req.reader.stack = reader->next;
    reader->crt->do_close(data, reader);
    curlx_free(reader);
    reader = data->req.reader.stack;
  }
}

/**
 * @brief Tear down both client stacks and reset request counters.
 *
 * Used when the transfer is done with its request/response cycle for good.
 * Unlike Curl_client_reset() this always discards the readers.
 *
 * @param[in,out] data Transfer to clean up.
 * @post No readers or writers remain, bytecount and headerline are 0.
 * @see Curl_client_reset()
 */
void Curl_client_cleanup(struct Curl_easy *data)
{
  cl_reset_reader(data);
  cl_reset_writer(data);

  data->req.bytecount = 0;
  data->req.headerline = 0;
}

/**
 * @brief Reset the client stacks between two requests of one transfer.
 *
 * The writer stack is always discarded. The reader stack is kept when a
 * rewind was requested (see Curl_creader_set_rewind()), so that the upload
 * data can be sent again by the next request; otherwise it is discarded.
 *
 * @param[in,out] data Transfer to reset.
 * @post Writer stack is empty, bytecount and headerline are 0.
 * @see Curl_client_start(), Curl_client_cleanup()
 */
void Curl_client_reset(struct Curl_easy *data)
{
  if(data->req.rewind_read) {
    /* already requested */
    CURL_TRC_READ(data, "client_reset, will rewind reader");
  }
  else {
    CURL_TRC_READ(data, "client_reset, clear readers");
    cl_reset_reader(data);
  }
  cl_reset_writer(data);

  data->req.bytecount = 0;
  data->req.headerline = 0;
}

/**
 * @brief Prepare the client readers for a new request.
 *
 * If a rewind was requested, every reader in the stack is sent
 * CURL_CRCNTRL_REWIND. When that succeeded the rewind flag is cleared and
 * the reader stack is dropped, to be rebuilt for the new request.
 *
 * @param[in,out] data Transfer about to start a request.
 * @return CURLE_OK on success or when no rewind was pending.
 * @return The error code of the first reader whose rewind failed (e.g.
 *         CURLE_SEND_FAIL_REWIND); the failure is also reported via failf().
 * @see Curl_creader_set_rewind()
 */
CURLcode Curl_client_start(struct Curl_easy *data)
{
  if(data->req.rewind_read) {
    struct Curl_creader *r = data->req.reader.stack;
    CURLcode result = CURLE_OK;

    CURL_TRC_READ(data, "client start, rewind readers");
    while(r) {
      result = r->crt->cntrl(data, r, CURL_CRCNTRL_REWIND);
      if(result) {
        failf(data, "rewind of client reader '%s' failed: %d",
              r->crt->name, (int)result);
        return result;
      }
      r = r->next;
    }
    data->req.rewind_read = FALSE;
    cl_reset_reader(data);
  }
  return CURLE_OK;
}

/**
 * @brief Tell if the reader stack is marked to be rewound at next start.
 *
 * @param[in] data Transfer to query.
 * @return TRUE if a rewind has been requested, FALSE otherwise.
 */
bool Curl_creader_will_rewind(struct Curl_easy *data)
{
  return (bool)data->req.rewind_read;
}

/**
 * @brief Request (or cancel) a rewind of the readers before the next request.
 *
 * @param[in,out] data   Transfer to modify.
 * @param[in]     enable TRUE to request a rewind, FALSE to cancel it.
 * @see Curl_client_start()
 */
void Curl_creader_set_rewind(struct Curl_easy *data, bool enable)
{
  data->req.rewind_read = !!enable;
}

/**
 * @brief Default do_init() handler for client writers: does nothing.
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] writer Writer being initialized (unused).
 * @return CURLE_OK always.
 */
CURLcode Curl_cwriter_def_init(struct Curl_easy *data,
                               struct Curl_cwriter *writer)
{
  (void)data;
  (void)writer;
  return CURLE_OK;
}

/**
 * @brief Default do_write() handler: pass the data to the next writer.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] writer Writer whose successor receives the data.
 * @param[in]     type   CLIENTWRITE_* bit mask describing the data.
 * @param[in]     buf    Data to write, not copied.
 * @param[in]     nbytes Number of bytes in buf.
 * @return Result of the next writer (CURLE_OK on success).
 * @pre writer->next must not be NULL; the last writer in a stack must
 *      implement its own do_write().
 */
CURLcode Curl_cwriter_def_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t nbytes)
{
  return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
}

/**
 * @brief Default do_flush() handler: flush the next writer.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] writer Writer whose successor is flushed.
 * @param[in]     eos    TRUE if the end of the stream has been reached.
 * @return Result of the next writer's flush (CURLE_OK on success).
 */
CURLcode Curl_cwriter_def_flush(struct Curl_easy *data,
                                struct Curl_cwriter *writer, bool eos)
{
  return Curl_cwriter_flush(data, writer->next, eos);
}

/**
 * @brief Default do_close() handler for client writers: does nothing.
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] writer Writer being closed (unused).
 */
void Curl_cwriter_def_close(struct Curl_easy *data,
                            struct Curl_cwriter *writer)
{
  (void)data;
  (void)writer;
}

/**
 * @brief Compute how many more body bytes may be written under a limit.
 * @internal
 *
 * @param[in] data  Transfer, its req.bytecount counts bytes already written.
 * @param[in] limit Maximum allowed body size, or -1 for "no limit".
 * @return SIZE_MAX if limit is -1, otherwise limit minus bytecount clamped
 *         to the range 0..SIZE_MAX.
 */
static size_t get_max_body_write_len(struct Curl_easy *data, curl_off_t limit)
{
  if(limit != -1) {
    /* How much more are we allowed to write? */
    return curlx_sotouz_range(limit - data->req.bytecount, 0, SIZE_MAX);
  }
  return SIZE_MAX;
}

/**
 * @brief Context of the download writer (phase CURL_CW_PROTOCOL).
 * @internal
 */
struct cw_download_ctx {
  struct Curl_cwriter super;  ///< base writer, must be first
  BIT(started_response);  ///< response start time recorded
  BIT(started_body);  ///< download rate limit started
};

/**
 * @brief Download writer in phase CURL_CW_PROTOCOL.
 * @internal
 *
 * Sees the real response data once all transfer and content decoding is
 * done. For headers it only forwards them (honoring suppression of CONNECT
 * headers). For body bytes it checks them against the announced size, the
 * CURLOPT_MAXFILESIZE limit and "no body expected" conditions, forwards the
 * permitted part, and updates byte counters and download progress. Starts
 * the TIMER_STARTTRANSFER timer and the download rate limiter on first use.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] writer This writer, its ctx is a struct cw_download_ctx.
 * @param[in]     type   CLIENTWRITE_* bit mask of the data.
 * @param[in]     buf    Data to write.
 * @param[in]     nbytes Length of buf.
 * @return CURLE_OK on success.
 * @return CURLE_WEIRD_SERVER_REPLY if a body arrives when none is wanted
 *         and no headers were received.
 * @return CURLE_PARTIAL_FILE if the response ended before the announced
 *         size was delivered.
 * @return CURLE_FILESIZE_EXCEEDED if the maximum file size was exceeded.
 * @return Any error returned by the next writer.
 * @note Excess bytes beyond the announced size are dropped and the
 *       connection is marked for closing.
 */
static CURLcode cw_download_write(struct Curl_easy *data,
                                  struct Curl_cwriter *writer, int type,
                                  const char *buf, size_t nbytes)
{
  struct cw_download_ctx *ctx = writer->ctx;
  CURLcode result;
  size_t nwrite, excess_len = 0;
  bool is_connect = !!(type & CLIENTWRITE_CONNECT);

  if(!ctx->started_response &&
     !(type & CLIENTWRITE_CONNECT) &&
     (!(type & CLIENTWRITE_INFO) || data->req.upload_done)) {
    Curl_pgrsTime(data, TIMER_STARTTRANSFER);
    ctx->started_response = TRUE;
  }

  if(!(type & CLIENTWRITE_BODY)) {
    if(is_connect && data->set.suppress_connect_headers)
      return CURLE_OK;
#ifdef DEBUGBUILD
    if(is_connect && getenv("CURL_DBG_SUPPRESS_CONNECT_HDS"))
      return CURLE_OK;
#endif
    result = Curl_cwriter_write(data, writer->next, type, buf, nbytes);
    CURL_TRC_WRITE(data, "download_write header(type=%x, blen=%zu) -> %d",
                   (unsigned int)type, nbytes, (int)result);
    return result;
  }

  if(!ctx->started_body &&
     !(type & (CLIENTWRITE_INFO | CLIENTWRITE_CONNECT))) {
    Curl_rlimit_start(&data->progress.dl.rlimit, Curl_pgrs_now(data),
                      data->req.size);
    ctx->started_body = TRUE;
  }

  /* Here, we deal with REAL BODY bytes. All filtering and transfer
   * encodings have been applied and only the true content, e.g. BODY,
   * bytes are passed here.
   * This allows us to check sizes, update stats, etc. independent
   * from the protocol in play. */

  if(data->req.no_body && nbytes > 0) {
    /* BODY arrives although we want none, bail out */
    streamclose(data->conn);
    CURL_TRC_WRITE(data, "download_write body(type=%x, blen=%zu), "
                   "did not want a BODY", (unsigned int)type, nbytes);
    data->req.download_done = TRUE;
    if(data->info.header_size)
      /* if headers have been received, this is fine */
      return CURLE_OK;
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* Determine if we see any bytes in excess to what is allowed.
   * We write the allowed bytes and handle excess further below.
   * This gives deterministic BODY writes on varying buffer receive
   * lengths. */
  nwrite = nbytes;
  if(data->req.maxdownload != -1) {
    size_t wmax = get_max_body_write_len(data, data->req.maxdownload);
    if(nwrite > wmax) {
      excess_len = nbytes - wmax;
      nwrite = wmax;
    }

    if(nwrite == wmax) {
      data->req.download_done = TRUE;
    }

    if((type & CLIENTWRITE_EOS) && !data->req.no_body &&
       (data->req.size > data->req.bytecount)) {
      failf(data, "end of response with %" FMT_OFF_T " bytes missing",
            data->req.size - data->req.bytecount);
      return CURLE_PARTIAL_FILE;
    }
  }

  /* Error on too large filesize is handled below, after writing
   * the permitted bytes */
  if(data->set.max_filesize && !data->req.ignorebody) {
    size_t wmax = get_max_body_write_len(data, data->set.max_filesize);
    if(nwrite > wmax) {
      nwrite = wmax;
    }
  }

  if(!data->req.ignorebody && (nwrite || (type & CLIENTWRITE_EOS))) {
    result = Curl_cwriter_write(data, writer->next, type, buf, nwrite);
    CURL_TRC_WRITE(data, "download_write body(type=%x, blen=%zu) -> %d",
                   (unsigned int)type, nbytes, (int)result);
    if(result)
      return result;
  }

  /* Update stats, write and report progress */
  if(nwrite) {
    data->req.bytecount += nwrite;
    Curl_pgrs_download_inc(data, nwrite);
  }

  if(excess_len) {
    if(!data->req.ignorebody) {
      infof(data,
            "Excess found writing body:"
            " excess = %zu"
            ", size = %" FMT_OFF_T
            ", maxdownload = %" FMT_OFF_T
            ", bytecount = %" FMT_OFF_T,
            excess_len, data->req.size, data->req.maxdownload,
            data->req.bytecount);
      connclose(data->conn);
    }
  }
  else if((nwrite < nbytes) && !data->req.ignorebody) {
    failf(data, "Exceeded the maximum allowed file size "
          "(%" FMT_OFF_T ") with %" FMT_OFF_T " bytes",
          data->set.max_filesize, data->req.bytecount);
    return CURLE_FILESIZE_EXCEEDED;
  }

  return CURLE_OK;
}

/**
 * @brief Type descriptor of the download writer ("protocol").
 * @internal
 */
static const struct Curl_cwtype cw_download = {
  "protocol",
  NULL,
  0,
  Curl_cwriter_def_init,
  cw_download_write,
  Curl_cwriter_def_flush,
  Curl_cwriter_def_close,
  sizeof(struct cw_download_ctx)
};

/**
 * @brief RAW client writer in phase CURL_CW_RAW.
 * @internal
 *
 * Enables tracing of the raw (still encoded) body data when verbose output
 * is on, then forwards everything unchanged to the next writer.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] writer This writer.
 * @param[in]     type   CLIENTWRITE_* bit mask of the data.
 * @param[in]     buf    Data to write.
 * @param[in]     nbytes Length of buf.
 * @return Result of the next writer.
 */
static CURLcode cw_raw_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes)
{
  if(type & CLIENTWRITE_BODY && data->set.verbose && !data->req.ignorebody) {
    Curl_debug(data, CURLINFO_DATA_IN, buf, nbytes);
  }
  return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
}

/**
 * @brief Type descriptor of the raw tracing writer ("raw").
 * @internal
 */
static const struct Curl_cwtype cw_raw = {
  "raw",
  NULL,
  0,
  Curl_cwriter_def_init,
  cw_raw_write,
  Curl_cwriter_def_flush,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

/**
 * @brief Link a writer into the stack as first of its phase.
 * @internal
 *
 * Writers of lower phases stay in front. Cannot fail.
 *
 * @param[in,out] data   Transfer owning the writer stack.
 * @param[in]     writer Initialized writer, ownership moves to the stack.
 */
static void cwriter_add(struct Curl_easy *data,
                        struct Curl_cwriter *writer)
{
  struct Curl_cwriter **anchor = &data->req.writer.stack;

  /* Insert the writer as first in its phase.
   * Skip existing writers of lower phases. */
  while(*anchor && (*anchor)->phase < writer->phase)
    anchor = &(*anchor)->next;
  writer->next = *anchor;
  *anchor = writer;
}

/**
 * @brief Create the default writer stack.
 * @internal
 *
 * Installs the client output writer, the download writer and the raw
 * tracing writer.
 *
 * @param[in,out] data Transfer, its writer stack must still be empty.
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY or the error of a writer's do_init().
 */
static CURLcode do_init_writer_stack(struct Curl_easy *data)
{
  struct Curl_cwriter *writer;
  CURLcode result;

  DEBUGASSERT(!data->req.writer.stack);
  result = Curl_cwriter_create(&data->req.writer.stack,
                               data, &Curl_cwt_out, CURL_CW_CLIENT);
  if(result)
    return result;

  result = Curl_cwriter_create(&writer, data, &cw_download, CURL_CW_PROTOCOL);
  if(result)
    return result;
  cwriter_add(data, writer);

  result = Curl_cwriter_create(&writer, data, &cw_raw, CURL_CW_RAW);
  if(result)
    return result;
  cwriter_add(data, writer);

  return result;
}

/* Curl_client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.
/**
 * @brief Send data to the client write callback(s) via the writer stack.
 *
 * The bit pattern in type defines to what "streams" to write: body and/or
 * header (the CLIENTWRITE_* defines are in sendf.h). The writer stack is
 * created on first use.
 *
 * @param[in,out] data Transfer.
 * @param[in]     type Bit mask of CLIENTWRITE_*. Must contain one of BODY,
 *                     HEADER or INFO; BODY and INFO may only be combined
 *                     with EOS.
 * @param[in]     buf  Data to write.
 * @param[in]     len  Length of buf.
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY if the stack could not be created.
 * @return Any error from a writer, e.g. CURLE_WRITE_ERROR from the
 *         application callback or CURLE_FILESIZE_EXCEEDED.
 * @see Curl_client_flush()
 */
CURLcode Curl_client_write(struct Curl_easy *data, int type, const char *buf,
                           size_t len)
{
  CURLcode result;

  /* it is one of those, at least */
  DEBUGASSERT(type &
              (CLIENTWRITE_BODY | CLIENTWRITE_HEADER | CLIENTWRITE_INFO));
  /* BODY is only BODY (with optional EOS) */
  DEBUGASSERT(!(type & CLIENTWRITE_BODY) ||
              ((type & ~(CLIENTWRITE_BODY | CLIENTWRITE_EOS)) == 0));
  /* INFO is only INFO (with optional EOS) */
  DEBUGASSERT(!(type & CLIENTWRITE_INFO) ||
              ((type & ~(CLIENTWRITE_INFO | CLIENTWRITE_EOS)) == 0));

  if(!data->req.writer.stack) {
    result = do_init_writer_stack(data);
    if(result)
      return result;
    DEBUGASSERT(data->req.writer.stack);
  }

  result = Curl_cwriter_write(data, data->req.writer.stack, type, buf, len);
  CURL_TRC_WRITE(data, "client_write(type=%x, len=%zu) -> %d",
                 (unsigned int)type, len, (int)result);
  return result;
}

/**
 * @brief Flush all client writers, e.g. buffered or paused data.
 *
 * @param[in,out] data Transfer.
 * @param[in]     eos  TRUE if no more data will follow.
 * @return CURLE_OK on success, otherwise the error of a writer's flush.
 * @see Curl_client_write()
 */
CURLcode Curl_client_flush(struct Curl_easy *data, bool eos)
{
  CURLcode result;

  if(!data->req.writer.stack) {
    result = do_init_writer_stack(data);
    if(result)
      return result;
    DEBUGASSERT(data->req.writer.stack);
  }

  result = Curl_cwriter_flush(data, data->req.writer.stack, eos);
  CURL_TRC_WRITE(data, "client_flush(eos=%d) -> %d", eos, (int)result);
  return result;
}

/**
 * @brief Create an unencoding writer stage using the given handler.
 *
 * Allocates a zeroed instance of cwt->cwriter_size bytes and calls the
 * type's do_init().
 *
 * @param[out] pwriter Receives the new writer, or NULL on failure.
 * @param[in]  data    Transfer.
 * @param[in]  cwt     Writer type, must outlive the writer.
 * @param[in]  phase   Phase in which the writer is to run.
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY if allocation failed, or the error returned
 *         by do_init() (the instance is freed in that case).
 * @note The caller owns the writer until it is added to a stack with
 *       Curl_cwriter_add().
 * @see Curl_cwriter_free()
 */
CURLcode Curl_cwriter_create(struct Curl_cwriter **pwriter,
                             struct Curl_easy *data,
                             const struct Curl_cwtype *cwt,
                             Curl_cwriter_phase phase)
{
  struct Curl_cwriter *writer = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  void *p;

  DEBUGASSERT(cwt->cwriter_size >= sizeof(struct Curl_cwriter));
  p = curlx_calloc(1, cwt->cwriter_size);
  if(!p)
    goto out;

  writer = (struct Curl_cwriter *)p;
  writer->cwt = cwt;
  writer->ctx = p;
  writer->phase = phase;
  result = cwt->do_init(data, writer);

out:
  *pwriter = result ? NULL : writer;
  if(result)
    curlx_free(writer);
  return result;
}

/**
 * @brief Close and free a writer that is not (or no longer) in a stack.
 *
 * @param[in] data   Transfer.
 * @param[in] writer Writer to destroy, may be NULL.
 * @warning The writer must not be linked in a stack, it is not unlinked.
 */
void Curl_cwriter_free(struct Curl_easy *data,
                       struct Curl_cwriter *writer)
{
  if(writer) {
    writer->cwt->do_close(data, writer);
    curlx_free(writer);
  }
}

/**
 * @brief Count writers installed in a given phase.
 *
 * @param[in] data  Transfer.
 * @param[in] phase Phase to count.
 * @return Number of writers in the stack with that phase.
 */
size_t Curl_cwriter_count(struct Curl_easy *data, Curl_cwriter_phase phase)
{
  struct Curl_cwriter *w;
  size_t n = 0;

  for(w = data->req.writer.stack; w; w = w->next) {
    if(w->phase == phase)
      ++n;
  }
  return n;
}

/**
 * @brief Make sure the pause writer exists in the stack.
 * @internal
 *
 * @param[in,out] data Transfer.
 * @return CURLE_OK if present or created, else the creation error.
 */
static CURLcode cwriter_ensure_pause_writer(struct Curl_easy *data)
{
  struct Curl_cwriter *writer =
    Curl_cwriter_get_by_type(data, &Curl_cwt_pause);
  CURLcode result = CURLE_OK;

  if(!writer) {
    result = Curl_cwriter_create(&writer, data, &Curl_cwt_pause,
                                 CURL_CW_BEFORE_DECODE);
    if(!result)
      cwriter_add(data, writer);
  }
  return result;
}

/**
 * @brief Add a writer to the transfer's writer stack.
 *
 * Creates the default stack first if needed. Writers that may inflate data
 * (CURL_CW_FLAG_BLOWUP, e.g. decompressors) get a pause writer installed
 * before them so that output can be held back.
 *
 * @param[in,out] data   Transfer.
 * @param[in]     writer Initialized writer to insert.
 * @return CURLE_OK on success, the writer is then owned by the stack.
 * @return An error when the stack or pause writer could not be created; the
 *         caller must then free the writer with Curl_cwriter_free().
 */
CURLcode Curl_cwriter_add(struct Curl_easy *data,
                          struct Curl_cwriter *writer)
{
  CURLcode result;
  struct Curl_cwriter **anchor = &data->req.writer.stack;

  if(!*anchor) {
    result = do_init_writer_stack(data);
    if(result)
      return result;
  }

  if(writer->cwt->flags & CURL_CW_FLAG_BLOWUP) {
    /* On adding a writer that may blow up write sizes, e.g. zip bombs,
     * add the pause writer. Do this first as any failure will make the
     * caller destroy the writer again. */
    result = cwriter_ensure_pause_writer(data);
    if(result)
      return result;
  }

  cwriter_add(data, writer);
  return CURLE_OK;
}

/**
 * @brief Find a writer in the stack by its type name.
 *
 * @param[in] data Transfer.
 * @param[in] name Name of the writer type, e.g. "raw".
 * @return The first matching writer, or NULL if none.
 * @note The returned pointer is owned by the stack.
 */
struct Curl_cwriter *Curl_cwriter_get_by_name(struct Curl_easy *data,
                                              const char *name)
{
  struct Curl_cwriter *writer;
  for(writer = data->req.writer.stack; writer; writer = writer->next) {
    if(!strcmp(name, writer->cwt->name))
      return writer;
  }
  return NULL;
}

/**
 * @brief Find a writer in the stack by its type descriptor.
 *
 * @param[in] data Transfer.
 * @param[in] cwt  Type descriptor to look for (compared by address).
 * @return The first matching writer, or NULL if none.
 * @note The returned pointer is owned by the stack.
 */
struct Curl_cwriter *Curl_cwriter_get_by_type(struct Curl_easy *data,
                                              const struct Curl_cwtype *cwt)
{
  struct Curl_cwriter *writer;
  for(writer = data->req.writer.stack; writer; writer = writer->next) {
    if(writer->cwt == cwt)
      return writer;
  }
  return NULL;
}

/**
 * @brief Resume writing after the application unpaused the transfer.
 *
 * Clears the paused flag and flushes the writer stack so held-back data is
 * delivered.
 *
 * @param[in,out] data Transfer.
 * @return CURLE_OK on success, or the error from flushing (which may be
 *         a pause request again).
 */
CURLcode Curl_cwriter_unpause(struct Curl_easy *data)
{
  data->req.writer.paused = FALSE;
  return Curl_cwriter_flush(data, data->req.writer.stack, FALSE);
}

/**
 * @brief Read upload data from a given reader.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader to read from, may be NULL.
 * @param[out]    buf    Buffer receiving data.
 * @param[in]     blen   Size of buf.
 * @param[out]    nread  Number of bytes placed in buf, 0 on error.
 * @param[out]    eos    TRUE when the reader reached its end.
 * @return CURLE_OK on success.
 * @return CURLE_READ_ERROR if reader is NULL, otherwise the reader's error
 *         (e.g. CURLE_ABORTED_BY_CALLBACK).
 */
CURLcode Curl_creader_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen, size_t *nread, bool *eos)
{
  *nread = 0;
  *eos = FALSE;
  if(!reader)
    return CURLE_READ_ERROR;
  return reader->crt->do_read(data, reader, buf, blen, nread, eos);
}

/**
 * @brief Tell the reader chain to forget a seen end-of-stream.
 *
 * Sends CURL_CRCNTRL_CLEAR_EOS to the reader and all those after it.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader First reader to notify, may be NULL.
 */
void Curl_creader_clear_eos(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  while(reader) {
    (void)reader->crt->cntrl(data, reader, CURL_CRCNTRL_CLEAR_EOS);
    reader = reader->next;
  }
}

/**
 * @brief Default do_init() handler for client readers: does nothing.
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] reader Reader being initialized (unused).
 * @return CURLE_OK always.
 */
CURLcode Curl_creader_def_init(struct Curl_easy *data,
                               struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

/**
 * @brief Default do_close() handler for client readers: does nothing.
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] reader Reader being closed (unused).
 */
void Curl_creader_def_close(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
}

/**
 * @brief Default do_read() handler: read from the next reader.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader whose successor is read.
 * @param[out]    buf    Buffer receiving data.
 * @param[in]     blen   Size of buf.
 * @param[out]    nread  Bytes read.
 * @param[out]    eos    TRUE at end of stream.
 * @return Result of the next reader.
 * @return CURLE_READ_ERROR (with nread 0, eos FALSE) if there is no next
 *         reader.
 */
CURLcode Curl_creader_def_read(struct Curl_easy *data,
                               struct Curl_creader *reader,
                               char *buf, size_t blen,
                               size_t *nread, bool *eos)
{
  if(reader->next)
    return reader->next->crt->do_read(data, reader->next, buf, blen,
                                      nread, eos);
  else {
    *nread = 0;
    *eos = FALSE;
    return CURLE_READ_ERROR;
  }
}

/**
 * @brief Default needs_rewind() handler.
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @return FALSE always.
 */
bool Curl_creader_def_needs_rewind(struct Curl_easy *data,
                                   struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return FALSE;
}

/**
 * @brief Default total_length() handler: ask the next reader.
 *
 * @param[in] data   Transfer.
 * @param[in] reader Reader whose successor is asked.
 * @return Total length of the upload in bytes, or -1 if unknown or there
 *         is no next reader.
 */
curl_off_t Curl_creader_def_total_length(struct Curl_easy *data,
                                         struct Curl_creader *reader)
{
  return reader->next ?
         reader->next->crt->total_length(data, reader->next) : -1;
}

/**
 * @brief Default resume_from() handler: resuming is not supported.
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @param[in] offset Offset to resume at (unused).
 * @return CURLE_READ_ERROR always.
 */
CURLcode Curl_creader_def_resume_from(struct Curl_easy *data,
                                      struct Curl_creader *reader,
                                      curl_off_t offset)
{
  (void)data;
  (void)reader;
  (void)offset;
  return CURLE_READ_ERROR;
}

/**
 * @brief Default cntrl() handler: ignore the control opcode.
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @param[in] opcode Control operation (unused).
 * @return CURLE_OK always.
 */
CURLcode Curl_creader_def_cntrl(struct Curl_easy *data,
                                struct Curl_creader *reader,
                                Curl_creader_cntrl opcode)
{
  (void)data;
  (void)reader;
  (void)opcode;
  return CURLE_OK;
}

/**
 * @brief Default is_paused() handler.
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @return FALSE always.
 */
bool Curl_creader_def_is_paused(struct Curl_easy *data,
                                struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return FALSE;
}

/**
 * @brief Default done() handler: does nothing.
 *
 * @param[in] data      Transfer (unused).
 * @param[in] reader    Reader (unused).
 * @param[in] premature Non-zero if the transfer ended early (unused).
 */
void Curl_creader_def_done(struct Curl_easy *data,
                           struct Curl_creader *reader, int premature)
{
  (void)data;
  (void)reader;
  (void)premature;
}

/**
 * @brief Context of the "cr-in" reader that feeds from the read callback.
 * @internal
 */
struct cr_in_ctx {
  struct Curl_creader super;  ///< base reader, must be first
  curl_read_callback read_cb;  ///< application read callback
  void *cb_user_data;  ///< user pointer for read_cb
  curl_off_t total_len;  ///< bytes to upload, -1 if unknown
  curl_off_t read_len;  ///< bytes read so far
  CURLcode error_result;  ///< sticky error to return
  BIT(seen_eos);  ///< end of input reached
  BIT(errored);  ///< a read failed, error is sticky
  BIT(has_used_cb);  ///< callback was invoked once
  BIT(is_paused);  ///< callback returned PAUSE
};

/**
 * @brief Initialize the cr-in reader from the transfer's read callback.
 * @internal
 *
 * @param[in]     data   Transfer providing fread_func and the user pointer.
 * @param[in,out] reader Reader, its ctx is a struct cr_in_ctx.
 * @return CURLE_OK always.
 */
static CURLcode cr_in_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  ctx->read_cb = data->state.fread_func;
  ctx->cb_user_data = data->state.in;
  ctx->total_len = -1;
  ctx->read_len = 0;
  return CURLE_OK;
}

/**
 * @brief Real client reader that calls the installed read callback.
 * @internal
 *
 * Respects a known total length, remembers EOS and errors (an error is
 * returned again on every later call), and handles the special callback
 * return values CURL_READFUNC_ABORT and CURL_READFUNC_PAUSE.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_in_ctx.
 * @param[out]    buf    Buffer receiving data.
 * @param[in]     blen   Size of buf.
 * @param[out]    pnread Bytes read.
 * @param[out]    peos   TRUE when the end of the input was reached.
 * @return CURLE_OK on success, also when the transfer got paused.
 * @return CURLE_READ_ERROR on premature EOF, an invalid callback return
 *         value or PAUSE for protocols that cannot pause.
 * @return CURLE_ABORTED_BY_CALLBACK if the callback returned
 *         CURL_READFUNC_ABORT.
 */
static CURLcode cr_in_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_in_ctx *ctx = reader->ctx;
  CURLcode result = CURLE_OK;
  size_t nread;

  ctx->is_paused = FALSE;

  /* Once we have errored, we will return the same error forever */
  if(ctx->errored) {
    *pnread = 0;
    *peos = FALSE;
    return ctx->error_result;
  }
  if(ctx->seen_eos) {
    *pnread = 0;
    *peos = TRUE;
    return CURLE_OK;
  }
  /* respect length limitations */
  if(ctx->total_len >= 0) {
    blen = curlx_sotouz_range(ctx->total_len - ctx->read_len, 0, blen);
  }
  nread = 0;
  if(ctx->read_cb && blen) {
    struct Curl_mapi_guard guard;
    CURL_CBAPI_START(&guard, data, easy_cr_in_read);
    nread = ctx->read_cb(buf, 1, blen, ctx->cb_user_data);
    CURL_CBAPI_END(&guard);
    ctx->has_used_cb = TRUE;
  }

  switch(nread) {
  case 0:
    if((ctx->total_len >= 0) && (ctx->read_len < ctx->total_len)) {
      failf(data, "client read function EOF fail, "
            "only %" FMT_OFF_T "/%" FMT_OFF_T " of needed bytes read",
            ctx->read_len, ctx->total_len);
      result = CURLE_READ_ERROR;
      break;
    }
    *pnread = 0;
    *peos = TRUE;
    ctx->seen_eos = TRUE;
    break;

  case CURL_READFUNC_ABORT:
    failf(data, "operation aborted by callback");
    *pnread = 0;
    *peos = FALSE;
    ctx->errored = TRUE;
    ctx->error_result = CURLE_ABORTED_BY_CALLBACK;
    result = CURLE_ABORTED_BY_CALLBACK;
    break;

  case CURL_READFUNC_PAUSE:
    if(data->conn->scheme->flags & PROTOPT_NONETWORK) {
      /* protocols that work without network cannot be paused. This is
         actually only file:// now, and it cannot pause since the transfer
         is not done using the "normal" procedure. */
      failf(data, "Read callback asked for PAUSE when not supported");
      result = CURLE_READ_ERROR;
      break;
    }
    /* CURL_READFUNC_PAUSE pauses read callbacks that feed socket writes */
    CURL_TRC_READ(data, "cr_in_read, callback returned CURL_READFUNC_PAUSE");
    ctx->is_paused = TRUE;
    *pnread = 0;
    *peos = FALSE;
    result = Curl_xfer_pause_send(data, TRUE);
    break; /* nothing was read */

  default:
    if(nread > blen) {
      /* the read function returned a too large value */
      failf(data, "read function returned funny value");
      *pnread = 0;
      *peos = FALSE;
      ctx->errored = TRUE;
      ctx->error_result = CURLE_READ_ERROR;
      result = CURLE_READ_ERROR;
      break;
    }
    ctx->read_len += nread;
    if(ctx->total_len >= 0)
      ctx->seen_eos = (ctx->read_len >= ctx->total_len);
    *pnread = nread;
    *peos = (bool)ctx->seen_eos;
    break;
  }
  CURL_TRC_READ(data, "cr_in_read(len=%zu, total=%" FMT_OFF_T
                ", read=%" FMT_OFF_T ") -> %d, nread=%zu, eos=%d",
                blen, ctx->total_len, ctx->read_len, (int)result,
                *pnread, *peos);
  return result;
}

/**
 * @brief cr-in needs_rewind(): TRUE once the callback has been used.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader, ctx is a struct cr_in_ctx.
 * @return TRUE if the read callback was ever invoked, else FALSE.
 */
static bool cr_in_needs_rewind(struct Curl_easy *data,
                               struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return (bool)ctx->has_used_cb;
}

/**
 * @brief cr-in total_length(): the announced upload size.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader, ctx is a struct cr_in_ctx.
 * @return Remaining total length in bytes, or -1 if unknown.
 */
static curl_off_t cr_in_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->total_len;
}

/**
 * @brief cr-in resume_from(): skip the first bytes of the input.
 * @internal
 *
 * Uses the seek callback if set. If seeking is impossible, the bytes are
 * read and discarded through the read callback. The total length is
 * reduced by the offset.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_in_ctx.
 * @param[in]     offset Number of bytes to skip.
 * @return CURLE_OK on success.
 * @return CURLE_READ_ERROR if reading already started, seeking failed or
 *         the input is shorter than offset.
 * @return CURLE_PARTIAL_FILE if nothing is left to upload after skipping.
 */
static CURLcode cr_in_resume_from(struct Curl_easy *data,
                                  struct Curl_creader *reader,
                                  curl_off_t offset)
{
  struct cr_in_ctx *ctx = reader->ctx;
  int seekerr = CURL_SEEKFUNC_CANTSEEK;

  DEBUGASSERT(data->conn);
  /* already started reading? */
  if(ctx->read_len)
    return CURLE_READ_ERROR;

  if(data->set.seek_func) {
    struct Curl_mapi_guard guard;
    CURL_CBAPI_START(&guard, data, easy_seek_func);
    seekerr = data->set.seek_func(data->set.seek_client, offset, SEEK_SET);
    CURL_CBAPI_END(&guard);
  }

  if(seekerr != CURL_SEEKFUNC_OK) {
    curl_off_t passed = 0;

    if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
      failf(data, "Could not seek stream");
      return CURLE_READ_ERROR;
    }
    /* when seekerr == CURL_SEEKFUNC_CANTSEEK (cannot seek to offset) */
    do {
      struct Curl_mapi_guard guard;
      char scratch[4 * 1024];
      size_t readthisamountnow =
        (offset - passed > (curl_off_t)sizeof(scratch)) ?
        sizeof(scratch) :
        curlx_sotouz(offset - passed);
      size_t actuallyread;

      CURL_CBAPI_START(&guard, data, easy_cr_in_resume_from);
      actuallyread = ctx->read_cb(scratch, 1, readthisamountnow,
                                  ctx->cb_user_data);
      CURL_CBAPI_END(&guard);

      passed += actuallyread;
      if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
        /* this checks for greater-than only to make sure that the
           CURL_READFUNC_ABORT return code still aborts */
        failf(data, "Could only read %" FMT_OFF_T " bytes from the input",
              passed);
        return CURLE_READ_ERROR;
      }
    } while(passed < offset);
  }

  /* now, decrease the size of the read */
  if(ctx->total_len > 0) {
    ctx->total_len -= offset;

    if(ctx->total_len <= 0) {
      failf(data, "File already completely uploaded");
      return CURLE_PARTIAL_FILE;
    }
  }
  /* we have passed, proceed as normal */
  return CURLE_OK;
}

/**
 * @brief cr-in rewind: reposition the input at its start.
 * @internal
 *
 * Tries, in order, the seek callback, the ioctl callback, and fseek() when
 * the default fread() on a FILE stream is in use.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_in_ctx.
 * @return CURLE_OK on success, or when the callback was never used.
 * @return CURLE_SEND_FAIL_REWIND if rewinding was not possible.
 */
static CURLcode cr_in_rewind(struct Curl_easy *data,
                             struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;

  /* If we never invoked the callback, there is noting to rewind */
  if(!ctx->has_used_cb)
    return CURLE_OK;

  if(data->set.seek_func) {
    struct Curl_mapi_guard guard;
    int err;

    CURL_CBAPI_START(&guard, data, easy_seek_func);
    err = data->set.seek_func(data->set.seek_client, 0, SEEK_SET);
    CURL_CBAPI_END(&guard);
    CURL_TRC_READ(data, "cr_in, rewind via set.seek_func -> %d", err);
    if(err) {
      failf(data, "seek callback returned error %d", err);
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  else if(data->set.ioctl_func) {
    struct Curl_mapi_guard guard;
    curlioerr err;

    CURL_CBAPI_START(&guard, data, easy_ioctl_func);
    err = data->set.ioctl_func(data, CURLIOCMD_RESTARTREAD,
                               data->set.ioctl_client);
    CURL_CBAPI_END(&guard);
    CURL_TRC_READ(data, "cr_in, rewind via set.ioctl_func -> %d", (int)err);
    if(err) {
      failf(data, "ioctl callback returned error %d", (int)err);
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  else {
    /* If no CURLOPT_READFUNCTION is used, we know that we operate on a
       given FILE * stream and we can actually attempt to rewind that
       ourselves with fseek() */
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
    if(data->state.fread_func == (curl_read_callback)fread) {
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
      int err = fseek(data->state.in, 0, SEEK_SET);
      CURL_TRC_READ(data, "cr_in, rewind via fseek -> %d(%d)",
                    (int)err, (int)errno);
      if(err != -1)
        /* successful rewind */
        return CURLE_OK;
    }

    /* no callback set or failure above, makes us fail at once */
    failf(data, "necessary data rewind was not possible");
    return CURLE_SEND_FAIL_REWIND;
  }
  return CURLE_OK;
}

/**
 * @brief cr-in cntrl(): handle REWIND, UNPAUSE and CLEAR_EOS.
 * @internal
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_in_ctx.
 * @param[in]     opcode Control operation; unknown ones are ignored.
 * @return CURLE_OK, or the result of the rewind for CURL_CRCNTRL_REWIND.
 */
static CURLcode cr_in_cntrl(struct Curl_easy *data,
                            struct Curl_creader *reader,
                            Curl_creader_cntrl opcode)
{
  struct cr_in_ctx *ctx = reader->ctx;

  switch(opcode) {
  case CURL_CRCNTRL_REWIND:
    return cr_in_rewind(data, reader);
  case CURL_CRCNTRL_UNPAUSE:
    ctx->is_paused = FALSE;
    break;
  case CURL_CRCNTRL_CLEAR_EOS:
    ctx->seen_eos = FALSE;
    break;
  default:
    break;
  }
  return CURLE_OK;
}

/**
 * @brief cr-in is_paused(): the callback asked to pause.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader, ctx is a struct cr_in_ctx.
 * @return TRUE if the last read returned CURL_READFUNC_PAUSE.
 */
static bool cr_in_is_paused(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return (bool)ctx->is_paused;
}

/**
 * @brief Type descriptor of the callback reader ("cr-in").
 * @internal
 */
static const struct Curl_crtype cr_in = {
  "cr-in",
  cr_in_init,
  cr_in_read,
  Curl_creader_def_close,
  cr_in_needs_rewind,
  cr_in_total_length,
  cr_in_resume_from,
  cr_in_cntrl,
  cr_in_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_in_ctx)
};

/**
 * @brief Create a client reader using the given type handler.
 *
 * Allocates a zeroed instance of crt->creader_size bytes and calls the
 * type's do_init().
 *
 * @param[out] preader Receives the new reader, or NULL on failure.
 * @param[in]  data    Transfer.
 * @param[in]  crt     Reader type, must outlive the reader.
 * @param[in]  phase   Phase in which the reader is to run.
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY if allocation failed, or the error returned
 *         by do_init() (the instance is freed in that case).
 * @note The caller owns the reader until it is added to a stack.
 * @see Curl_creader_free()
 */
CURLcode Curl_creader_create(struct Curl_creader **preader,
                             struct Curl_easy *data,
                             const struct Curl_crtype *crt,
                             Curl_creader_phase phase)
{
  struct Curl_creader *reader = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  void *p;

  DEBUGASSERT(crt->creader_size >= sizeof(struct Curl_creader));
  p = curlx_calloc(1, crt->creader_size);
  if(!p)
    goto out;

  reader = (struct Curl_creader *)p;
  reader->crt = crt;
  reader->ctx = p;
  reader->phase = phase;
  result = crt->do_init(data, reader);

out:
  *preader = result ? NULL : reader;
  if(result)
    curlx_free(reader);
  return result;
}

/**
 * @brief Close and free a reader that is not in a stack.
 *
 * @param[in] data   Transfer.
 * @param[in] reader Reader to destroy, may be NULL.
 * @warning The reader is not unlinked from any stack.
 */
void Curl_creader_free(struct Curl_easy *data, struct Curl_creader *reader)
{
  if(reader) {
    reader->crt->do_close(data, reader);
    curlx_free(reader);
  }
}

/**
 * @brief Context of the line-conversion reader "cr-lineconv".
 * @internal
 */
struct cr_lc_ctx {
  struct Curl_creader super;  ///< base reader, must be first
  struct bufq buf;  ///< converted data not yet delivered
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
  BIT(prev_cr);   /* the last byte was a CR */
};

/**
 * @brief Initialize the line-conversion reader's buffer queue.
 * @internal
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] reader Reader, ctx is a struct cr_lc_ctx.
 * @return CURLE_OK always.
 */
static CURLcode cr_lc_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  (void)data;
  Curl_bufq_init2(&ctx->buf, (16 * 1024), 1, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

/**
 * @brief Free the line-conversion reader's buffer queue.
 * @internal
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] reader Reader, ctx is a struct cr_lc_ctx.
 */
static void cr_lc_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  (void)data;
  Curl_bufq_free(&ctx->buf);
}

/**
 * @brief Client reader doing line end conversions (LF to CRLF).
 * @internal
 *
 * Reads from the next reader. If the data has no LF it is passed through,
 * otherwise it is copied into an internal queue with each lone LF replaced
 * by CRLF, and served from there. An LF that already follows a CR is kept.
 * The CR state is tracked across calls.
 *
 * @param[in,out] data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_lc_ctx.
 * @param[out]    buf    Buffer receiving data.
 * @param[in]     blen   Size of buf.
 * @param[out]    pnread Bytes read.
 * @param[out]    peos   TRUE when all data was delivered.
 * @return CURLE_OK on success, else the error of the next reader or of the
 *         buffer queue (e.g. CURLE_OUT_OF_MEMORY).
 */
static CURLcode cr_lc_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  CURLcode result;
  size_t nread, i, start, n;
  bool eos;

  if(ctx->eos) {
    *pnread = 0;
    *peos = TRUE;
    return CURLE_OK;
  }

  if(Curl_bufq_is_empty(&ctx->buf)) {
    if(ctx->read_eos) {
      ctx->eos = TRUE;
      *pnread = 0;
      *peos = TRUE;
      return CURLE_OK;
    }
    /* Still getting data form the next reader, ctx->buf is empty */
    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;
    ctx->read_eos = eos;

    if(!nread || !memchr(buf, '\n', nread)) {
      /* nothing to convert, return this right away */
      if(nread)
        ctx->prev_cr = (buf[nread - 1] == '\r');
      if(ctx->read_eos)
        ctx->eos = TRUE;
      *pnread = nread;
      *peos = (bool)ctx->eos;
      goto out;
    }

    /* at least one \n might need conversion to '\r\n', place into ctx->buf */
    for(i = start = 0; i < nread; ++i) {
      /* if this byte is not an LF character, or if the preceding character is
         a CR (meaning this already is a CRLF pair), go to next */
      if((buf[i] != '\n') || ctx->prev_cr) {
        ctx->prev_cr = (buf[i] == '\r');
        continue;
      }
      ctx->prev_cr = FALSE;
      /* on a soft limit bufq, we do not need to check length */
      result = Curl_bufq_cwrite(&ctx->buf, buf + start, i - start, &n);
      if(!result)
        result = Curl_bufq_cwrite(&ctx->buf, STRCONST("\r\n"), &n);
      if(result)
        return result;
      start = i + 1;
    }

    if(start < i) { /* leftover */
      result = Curl_bufq_cwrite(&ctx->buf, buf + start, i - start, &n);
      if(result)
        return result;
    }
  }

  DEBUGASSERT(!Curl_bufq_is_empty(&ctx->buf));
  *peos = FALSE;
  result = Curl_bufq_cread(&ctx->buf, buf, blen, pnread);
  if(!result && ctx->read_eos && Curl_bufq_is_empty(&ctx->buf)) {
    /* no more data, read all, done. */
    ctx->eos = TRUE;
    *peos = TRUE;
  }

out:
  CURL_TRC_READ(data, "cr_lc_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, (int)result, *pnread, *peos);
  return result;
}

/**
 * @brief cr-lineconv total_length(): size changes, so it is unknown.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @return -1 always.
 */
static curl_off_t cr_lc_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

/**
 * @brief Type descriptor of the line-conversion reader ("cr-lineconv").
 * @internal
 */
static const struct Curl_crtype cr_lc = {
  "cr-lineconv",
  cr_lc_init,
  cr_lc_read,
  cr_lc_close,
  Curl_creader_def_needs_rewind,
  cr_lc_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_lc_ctx)
};

/**
 * @brief Add the line-conversion reader to the reader stack.
 * @internal
 *
 * @param[in,out] data Transfer.
 * @return CURLE_OK on success, else the creation or insert error.
 */
static CURLcode cr_lc_add(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &cr_lc, CURL_CR_CONTENT_ENCODE);
  if(!result)
    result = Curl_creader_add(data, reader);

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

/**
 * @brief Install a client reader as the base of a new reader stack.
 * @internal
 *
 * Adds line-end conversion when CURLOPT_CRLF (or ASCII preference) is
 * active and the upload is not known to be empty.
 *
 * @param[in,out] data Transfer, its reader stack must be empty.
 * @param[in]     r    Reader of phase CURL_CR_CLIENT; ownership moves to
 *                     the stack.
 * @return CURLE_OK on success.
 * @return The error from adding the conversion reader. The stack is
 *         cleared (and r freed) in that case.
 */
static CURLcode do_init_reader_stack(struct Curl_easy *data,
                                     struct Curl_creader *r)
{
  CURLcode result = CURLE_OK;
  curl_off_t clen;

  DEBUGASSERT(r);
  DEBUGASSERT(r->crt);
  DEBUGASSERT(r->phase == CURL_CR_CLIENT);
  DEBUGASSERT(!data->req.reader.stack);

  data->req.reader.stack = r;
  clen = r->crt->total_length(data, r);
  /* if we do not have 0 length init, and CRLF conversion is wanted,
   * add the reader for it */
  if(clen &&
#ifdef CURL_PREFER_LF_LINEENDS
    (data->set.crlf || data->state.prefer_ascii)
#else
    data->set.crlf
#endif
    ) {
    result = cr_lc_add(data);
    if(result) {
      /* Adding the line-conversion reader failed. Undo the publication of
       * `r` so no freed reader remains reachable from
       * `data->req.reader.stack`, and free the readers already installed. */
      cl_reset_reader(data);
      return result;
    }
  }

  return result;
}

/**
 * @brief Set the client reader to use the application read callback.
 *
 * Replaces any existing reader stack.
 *
 * @param[in,out] data Transfer.
 * @param[in]     len  Total upload size in bytes, or -1 if unknown.
 * @return CURLE_OK on success.
 * @return CURLE_OUT_OF_MEMORY or another error from creating the readers.
 * @see Curl_creader_set_buf(), Curl_creader_set_null()
 */
CURLcode Curl_creader_set_fread(struct Curl_easy *data, curl_off_t len)
{
  CURLcode result;
  struct Curl_creader *r;
  struct cr_in_ctx *ctx;

  result = Curl_creader_create(&r, data, &cr_in, CURL_CR_CLIENT);
  if(result || !r)
    goto out;
  ctx = r->ctx;
  ctx->total_len = len;

  cl_reset_reader(data);
  result = do_init_reader_stack(data, r);
out:
  CURL_TRC_READ(data, "add fread reader, len=%" FMT_OFF_T " -> %d",
                len, (int)result);
  return result;
}

/**
 * @brief Add a reader to the transfer's reader stack.
 *
 * If there is no stack yet, the default callback reader is installed first
 * using data->state.infilesize. The reader is inserted as first of its
 * phase.
 *
 * @param[in,out] data   Transfer.
 * @param[in]     reader Initialized reader, ownership moves to the stack
 *                       on success.
 * @return CURLE_OK on success, otherwise an error; reader stays owned by
 *         the caller then.
 */
CURLcode Curl_creader_add(struct Curl_easy *data,
                          struct Curl_creader *reader)
{
  CURLcode result;
  struct Curl_creader **anchor = &data->req.reader.stack;

  if(!*anchor) {
    result = Curl_creader_set_fread(data, data->state.infilesize);
    if(result)
      return result;
  }

  /* Insert the writer as first in its phase.
   * Skip existing readers of lower phases. */
  while(*anchor && (*anchor)->phase < reader->phase)
    anchor = &(*anchor)->next;
  reader->next = *anchor;
  *anchor = reader;
  return CURLE_OK;
}

/**
 * @brief Replace the reader stack with the given client reader.
 *
 * @param[in,out] data Transfer.
 * @param[in]     r    Reader of phase CURL_CR_CLIENT; ownership moves to
 *                     the transfer.
 * @return CURLE_OK on success, else the error of do_init_reader_stack().
 */
CURLcode Curl_creader_set(struct Curl_easy *data, struct Curl_creader *r)
{
  DEBUGASSERT(r);
  DEBUGASSERT(r->crt);
  DEBUGASSERT(r->phase == CURL_CR_CLIENT);

  cl_reset_reader(data);
  return do_init_reader_stack(data, r);
}

/**
 * @brief Read upload data through the client reader stack.
 *
 * Creates the default callback reader when none is set, starts the upload
 * rate limiter on first call and caps blen to the currently available
 * quota. If the quota is used up, returns success with no data and eos
 * FALSE.
 *
 * @param[in,out] data  Transfer.
 * @param[out]    buf   Buffer receiving data, must not be NULL.
 * @param[in]     blen  Size of buf, must be non-zero.
 * @param[out]    nread Bytes read, may be 0.
 * @param[out]    eos   TRUE when the upload data is exhausted.
 * @return CURLE_OK on success.
 * @return Any error of the reader stack, e.g. CURLE_READ_ERROR or
 *         CURLE_ABORTED_BY_CALLBACK.
 */
CURLcode Curl_client_read(struct Curl_easy *data, char *buf, size_t blen,
                          size_t *nread, bool *eos)
{
  CURLcode result;

  DEBUGASSERT(buf);
  DEBUGASSERT(blen);
  DEBUGASSERT(nread);
  DEBUGASSERT(eos);
  *nread = 0;

  if(!data->req.reader.stack) {
    result = Curl_creader_set_fread(data, data->state.infilesize);
    if(result)
      return result;
    DEBUGASSERT(data->req.reader.stack);
  }
  if(!data->req.reader_started) {
    Curl_rlimit_start(&data->progress.ul.rlimit, Curl_pgrs_now(data), -1);
    data->req.reader_started = TRUE;
  }

  if(Curl_rlimit_active(&data->progress.ul.rlimit)) {
    curl_off_t ul_avail = Curl_rlimit_avail(&data->progress.ul.rlimit, NULL);
    if(ul_avail <= 0) {
      result = CURLE_OK;
      *eos = FALSE;
      goto out;
    }
    if(ul_avail < (curl_off_t)blen)
      blen = (size_t)ul_avail;
  }
  result = Curl_creader_read(data, data->req.reader.stack, buf, blen,
                             nread, eos);

out:
  CURL_TRC_READ(data, "client_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, (int)result, *nread, *eos);
  return result;
}

/**
 * @brief Tell if any reader needs a rewind before the next request.
 *
 * @param[in] data Transfer.
 * @return TRUE if at least one reader reports it consumed data.
 */
bool Curl_creader_needs_rewind(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader.stack;
  while(reader) {
    if(reader->crt->needs_rewind(data, reader)) {
      CURL_TRC_READ(data, "client reader needs rewind before next request");
      return TRUE;
    }
    reader = reader->next;
  }
  return FALSE;
}

/**
 * @brief cr-null read(): deliver no data and signal EOS.
 * @internal
 *
 * @param[in]  data   Transfer (unused).
 * @param[in]  reader Reader (unused).
 * @param[out] buf    Unused.
 * @param[in]  blen   Unused.
 * @param[out] pnread Set to 0.
 * @param[out] peos   Set to TRUE.
 * @return CURLE_OK always.
 */
static CURLcode cr_null_read(struct Curl_easy *data,
                             struct Curl_creader *reader,
                             char *buf, size_t blen,
                             size_t *pnread, bool *peos)
{
  (void)data;
  (void)reader;
  (void)buf;
  (void)blen;
  *pnread = 0;
  *peos = TRUE;
  return CURLE_OK;
}

/**
 * @brief cr-null total_length(): always empty.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader (unused).
 * @return 0 always.
 */
static curl_off_t cr_null_total_length(struct Curl_easy *data,
                                       struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return 0;
}

/**
 * @brief Type descriptor of the empty reader ("cr-null").
 * @internal
 */
static const struct Curl_crtype cr_null = {
  "cr-null",
  Curl_creader_def_init,
  cr_null_read,
  Curl_creader_def_close,
  Curl_creader_def_needs_rewind,
  cr_null_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct Curl_creader)
};

/**
 * @brief Set the client reader to one that provides no data at all.
 *
 * Replaces any existing reader stack.
 *
 * @param[in,out] data Transfer.
 * @return CURLE_OK on success, else the creation error.
 */
CURLcode Curl_creader_set_null(struct Curl_easy *data)
{
  struct Curl_creader *r;
  CURLcode result;

  result = Curl_creader_create(&r, data, &cr_null, CURL_CR_CLIENT);
  if(result)
    return result;

  cl_reset_reader(data);
  return do_init_reader_stack(data, r);
}

/**
 * @brief Context of the "cr-buf" reader that serves a memory buffer.
 * @internal
 */
struct cr_buf_ctx {
  struct Curl_creader super;  ///< base reader, must be first
  const char *buf;  ///< caller owned data, not copied
  size_t blen;  ///< bytes remaining in buf
  size_t index;  ///< read position in buf
};

/**
 * @brief cr-buf read(): copy from the memory buffer.
 * @internal
 *
 * @param[in,out] data   Transfer (used for tracing).
 * @param[in,out] reader Reader, ctx is a struct cr_buf_ctx.
 * @param[out]    buf    Buffer receiving data.
 * @param[in]     blen   Size of buf.
 * @param[out]    pnread Bytes copied.
 * @param[out]    peos   TRUE when the whole buffer has been delivered.
 * @return CURLE_OK always.
 */
static CURLcode cr_buf_read(struct Curl_easy *data,
                            struct Curl_creader *reader,
                            char *buf, size_t blen,
                            size_t *pnread, bool *peos)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  size_t nread = ctx->blen - ctx->index;

  if(!nread || !ctx->buf) {
    *pnread = 0;
    *peos = TRUE;
  }
  else {
    if(nread > blen)
      nread = blen;
    memcpy(buf, ctx->buf + ctx->index, nread);
    *pnread = nread;
    ctx->index += nread;
    *peos = (ctx->index == ctx->blen);
  }
  CURL_TRC_READ(data, "cr_buf_read(len=%zu) -> 0, nread=%zu, eos=%d",
                blen, *pnread, *peos);
  return CURLE_OK;
}

/**
 * @brief cr-buf needs_rewind(): TRUE once data has been read.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader, ctx is a struct cr_buf_ctx.
 * @return TRUE if the read position is past the start.
 */
static bool cr_buf_needs_rewind(struct Curl_easy *data,
                                struct Curl_creader *reader)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->index > 0;
}

/**
 * @brief cr-buf cntrl(): rewind resets the read position.
 * @internal
 *
 * @param[in]     data   Transfer (unused).
 * @param[in,out] reader Reader, ctx is a struct cr_buf_ctx.
 * @param[in]     opcode Control operation; only REWIND has an effect.
 * @return CURLE_OK always.
 */
static CURLcode cr_buf_cntrl(struct Curl_easy *data,
                             struct Curl_creader *reader,
                             Curl_creader_cntrl opcode)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  (void)data;
  switch(opcode) {
  case CURL_CRCNTRL_REWIND:
    ctx->index = 0;
    break;
  default:
    break;
  }
  return CURLE_OK;
}

/**
 * @brief cr-buf total_length(): size of the memory buffer.
 * @internal
 *
 * @param[in] data   Transfer (unused).
 * @param[in] reader Reader, ctx is a struct cr_buf_ctx.
 * @return Remaining buffer length in bytes.
 */
static curl_off_t cr_buf_total_length(struct Curl_easy *data,
                                      struct Curl_creader *reader)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  (void)data;
  return (curl_off_t)ctx->blen;
}

/**
 * @brief cr-buf resume_from(): skip the first bytes of the buffer.
 * @internal
 *
 * @param[in]     data   Transfer.
 * @param[in,out] reader Reader, ctx is a struct cr_buf_ctx.
 * @param[in]     offset Number of bytes to skip.
 * @return CURLE_OK on success.
 * @return CURLE_READ_ERROR if data was already read or offset is larger
 *         than the buffer.
 */
static CURLcode cr_buf_resume_from(struct Curl_easy *data,
                                   struct Curl_creader *reader,
                                   curl_off_t offset)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  size_t boffset;

  (void)data;
  DEBUGASSERT(data->conn);
  /* already started reading? */
  if(ctx->index)
    return CURLE_READ_ERROR;
  boffset = curlx_sotouz_range(offset, 0, SIZE_MAX);
  if(!boffset)
    return CURLE_OK;
  if(boffset > ctx->blen)
    return CURLE_READ_ERROR;

  ctx->buf += boffset;
  ctx->blen -= boffset;
  return CURLE_OK;
}

/**
 * @brief Type descriptor of the memory buffer reader ("cr-buf").
 * @internal
 */
static const struct Curl_crtype cr_buf = {
  "cr-buf",
  Curl_creader_def_init,
  cr_buf_read,
  Curl_creader_def_close,
  cr_buf_needs_rewind,
  cr_buf_total_length,
  cr_buf_resume_from,
  cr_buf_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_buf_ctx)
};

/**
 * @brief Set the client reader to serve data from a memory buffer.
 *
 * Replaces any existing reader stack.
 *
 * @param[in,out] data Transfer.
 * @param[in]     buf  Data to upload.
 * @param[in]     blen Length of buf.
 * @return CURLE_OK on success, else the creation error.
 * @warning buf is not copied and must stay valid while the transfer reads.
 */
CURLcode Curl_creader_set_buf(struct Curl_easy *data,
                              const char *buf, size_t blen)
{
  CURLcode result;
  struct Curl_creader *r;
  struct cr_buf_ctx *ctx;

  result = Curl_creader_create(&r, data, &cr_buf, CURL_CR_CLIENT);
  if(result)
    goto out;
  ctx = r->ctx;
  ctx->buf = buf;
  ctx->blen = blen;
  ctx->index = 0;

  cl_reset_reader(data);
  result = do_init_reader_stack(data, r);
out:
  CURL_TRC_READ(data, "add buf reader, len=%zu -> %d", blen, (int)result);
  return result;
}

/**
 * @brief Get the total upload length as seen after all readers.
 *
 * @param[in] data Transfer.
 * @return Length in bytes, or -1 if unknown or there is no reader.
 * @see Curl_creader_client_length()
 */
curl_off_t Curl_creader_total_length(struct Curl_easy *data)
{
  struct Curl_creader *r = data->req.reader.stack;
  return r ? r->crt->total_length(data, r) : -1;
}

/**
 * @brief Get the upload length of the client (phase CLIENT) reader.
 *
 * Unlike Curl_creader_total_length() this ignores converting readers.
 *
 * @param[in] data Transfer.
 * @return Length in bytes, or -1 if unknown or there is no such reader.
 */
curl_off_t Curl_creader_client_length(struct Curl_easy *data)
{
  struct Curl_creader *r = data->req.reader.stack;
  while(r && r->phase != CURL_CR_CLIENT)
    r = r->next;
  return r ? r->crt->total_length(data, r) : -1;
}

/**
 * @brief Tell all readers that the transfer was unpaused.
 *
 * @param[in,out] data Transfer.
 * @return CURLE_OK, or the first error from a reader's cntrl().
 */
CURLcode Curl_creader_unpause(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader.stack;
  CURLcode result = CURLE_OK;

  while(reader) {
    result = reader->crt->cntrl(data, reader, CURL_CRCNTRL_UNPAUSE);
    CURL_TRC_READ(data, "unpausing %s -> %d", reader->crt->name, (int)result);
    if(result)
      break;
    reader = reader->next;
  }
  return result;
}

/**
 * @brief Tell if any reader is paused.
 *
 * @param[in] data Transfer.
 * @return TRUE if at least one reader reports being paused.
 */
bool Curl_creader_is_paused(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader.stack;

  while(reader) {
    if(reader->crt->is_paused(data, reader))
      return TRUE;
    reader = reader->next;
  }
  return FALSE;
}

/**
 * @brief Notify all readers that the upload is done.
 *
 * @param[in,out] data      Transfer.
 * @param[in]     premature Non-zero if the transfer ended early.
 */
void Curl_creader_done(struct Curl_easy *data, int premature)
{
  struct Curl_creader *reader = data->req.reader.stack;
  while(reader) {
    reader->crt->done(data, reader, premature);
    reader = reader->next;
  }
}

/**
 * @brief Find a reader in the stack by its type descriptor.
 *
 * @param[in] data Transfer.
 * @param[in] crt  Type descriptor to look for (compared by address).
 * @return The first matching reader, or NULL if none.
 * @note The returned pointer is owned by the stack.
 */
struct Curl_creader *Curl_creader_get_by_type(struct Curl_easy *data,
                                              const struct Curl_crtype *crt)
{
  struct Curl_creader *r;
  for(r = data->req.reader.stack; r; r = r->next) {
    if(r->crt == crt)
      return r;
  }
  return NULL;
}
