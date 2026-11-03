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
 * @file progress.c
 * @brief Transfer progress accounting, timing and speed limit checks.
 *
 * This file keeps the bookkeeping that backs the progress meter, the
 * application progress callbacks (CURLOPT_XFERINFOFUNCTION and the older
 * CURLOPT_PROGRESSFUNCTION), the CURLINFO_*_TIME timers and the
 * CURLOPT_LOW_SPEED_LIMIT / CURLOPT_LOW_SPEED_TIME check.
 *
 * All state lives in struct Progress inside struct Curl_easy
 * (data->progress). Nothing here is synchronized: a handle must only be used
 * by one thread at a time, as everywhere else in libcurl.
 *
 * @defgroup pgrs Progress tracking
 * @brief Internal progress, timer and speed accounting helpers.
 * @internal
 * @{
 */
#include "curl_setup.h"

#include "urldata.h"
#include "curl_trc.h"
#include "multiif.h"
#include "progress.h"
#include "transfer.h"
#include "curlx/strcopy.h"

#ifndef CURL_DISABLE_PROGRESS_METER
/**
 * @brief Format a duration as a fixed width string for the progress meter.
 *
 * Produces a string that is exactly 7 letters long (plus the zero byte)
 * and picks the unit by magnitude: "H:MM:SS", "  MM:SS", "HHh MMm",
 * "DDd HHh", "DDDd", "MMMm" (months) or "YYYYYy". Non-positive input yields
 * seven spaces and values above 99999 years yield ">99999y".
 *
 * @param[out] r       Destination buffer, at least 8 bytes.
 * @param[in]  rsize   Size of @p r in bytes.
 * @param[in]  seconds Duration in seconds; values <= 0 mean "unknown".
 *
 * @note Output is truncated if @p rsize is too small.
 * @internal
 * @see progress_meter()
 * @unittest 1636
 */
UNITTEST void time2str(char *r, size_t rsize, curl_off_t seconds);
UNITTEST void time2str(char *r, size_t rsize, curl_off_t seconds)
{
  curl_off_t h;
  if(seconds <= 0) {
    curlx_strcopy(r, rsize, STRCONST("       "));
    return;
  }
  h = seconds / 3600;
  if(h <= 99) {
    curl_off_t m = (seconds - (h * 3600)) / 60;
    if(h <= 9) {
      curl_off_t s = (seconds - (h * 3600)) - (m * 60);
      if(h)
        curl_msnprintf(r, rsize, "%" FMT_OFF_T ":%02" FMT_OFF_T ":"
                       "%02" FMT_OFF_T, h, m, s);
      else
        curl_msnprintf(r, rsize, "  %02" FMT_OFF_T ":%02" FMT_OFF_T, m, s);
    }
    else
      curl_msnprintf(r, rsize, "%" FMT_OFF_T "h %02" FMT_OFF_T "m", h, m);
  }
  else {
    curl_off_t d = seconds / 86400;
    h = (seconds - (d * 86400)) / 3600;
    if(d <= 99)
      curl_msnprintf(r, rsize, "%2" FMT_OFF_T "d %02" FMT_OFF_T "h", d, h);
    else if(d <= 999)
      curl_msnprintf(r, rsize, "%6" FMT_OFF_T "d", d);
    else { /* more than 999 days */
      curl_off_t m = d / 30;
      if(m <= 999)
        curl_msnprintf(r, rsize, "%6" FMT_OFF_T "m", m);
      else { /* more than 999 months */
        curl_off_t y = d / 365;
        if(y <= 99999)
          curl_msnprintf(r, rsize, "%6" FMT_OFF_T "y", y);
        else
          curlx_strcopy(r, rsize, STRCONST(">99999y"));
      }
    }
  }
}

/**
 * @brief Render a byte count in at most 6 columns (plus the zero byte).
 *
 * Values below 100000 are printed as plain numbers. Larger values are
 * scaled by 1024 and get a suffix k, M, G, T, P or E, printed as "xx.yyU"
 * or "xxx.yU". A signed 64-bit value is at most 8192 petabytes, shown as
 * 8.0E (exabytes), so the unit table can never run out.
 *
 * @param[in]  bytes  Number of bytes (non-negative).
 * @param[out] max6   Destination buffer, at least 7 bytes.
 * @param[in]  mlen   Size of @p max6 in bytes.
 * @return The @p max6 pointer, to allow use directly as a format argument.
 *
 * @warning The returned pointer aliases the caller's buffer; it is only
 *          valid as long as that buffer is.
 * @internal
 * @see progress_meter()
 * @unittest 1636
 */
UNITTEST char *max6out(curl_off_t bytes, char *max6, size_t mlen);
UNITTEST char *max6out(curl_off_t bytes, char *max6, size_t mlen)
{
  /* a signed 64-bit value is 8192 petabytes maximum, shown as
     8.0E (exabytes)*/
  if(bytes < 100000)
    curl_msnprintf(max6, mlen, "%6" CURL_FORMAT_CURL_OFF_T, bytes);
  else {
    static const char unit[] = { 'k', 'M', 'G', 'T', 'P', 'E', 0 };
    int k = 0;
    curl_off_t nbytes;
    curl_off_t rest;
    do {
      nbytes = bytes / 1024;
      if(nbytes < 1000)
        break;
      bytes = nbytes;
      k++;
      DEBUGASSERT(unit[k]);
    } while(unit[k]);
    rest = bytes % 1024;
    if(nbytes <= 99)
      /* xx.yyU */
      curl_msnprintf(max6, mlen, "%2" CURL_FORMAT_CURL_OFF_T
                     ".%02" CURL_FORMAT_CURL_OFF_T "%c", nbytes,
                     rest * 100 / 1024, unit[k]);
    else
      /* xxx.yU */
      curl_msnprintf(max6, mlen, "%3" CURL_FORMAT_CURL_OFF_T
                     ".%" CURL_FORMAT_CURL_OFF_T "%c", nbytes,
                     rest * 10 / 1024, unit[k]);
  }
  return max6;
}
#endif

/**
 * @brief Restart the low-speed measurement.
 *
 * Clears the moment since which the transfer has been below the low speed
 * limit, so the next check starts counting from scratch.
 *
 * @param[in,out] data  Easy handle whose state.keeps_speed is cleared.
 * @internal
 * @see pgrs_speedcheck()
 */
static void pgrs_speedinit(struct Curl_easy *data)
{
  memset(&data->state.keeps_speed, 0, sizeof(struct curltime));
}

/**
 * @brief Enforce CURLOPT_LOW_SPEED_LIMIT / CURLOPT_LOW_SPEED_TIME.
 *
 * If the current speed stays below the limit for at least the configured
 * number of seconds, the transfer is failed. When the check is active, an
 * EXPIRE_SPEEDCHECK timer is armed so that the speed is looked at again in
 * one second, even if no socket activity happens.
 *
 * Paused transfers (either direction) and handles without both low speed
 * options set are never checked.
 *
 * @param[in,out] data  Easy handle to check.
 * @param[in]     pnow  Current time, not NULL.
 * @return CURLE_OK when the transfer is fast enough, not checked or the
 *         grace time has not run out yet.
 * @return CURLE_OPERATION_TIMEDOUT when it has been too slow for too long.
 * @internal
 * @unittest 1606
 */
UNITTEST CURLcode pgrs_speedcheck(struct Curl_easy *data,
                                  const struct curltime *pnow);
UNITTEST CURLcode pgrs_speedcheck(struct Curl_easy *data,
                                  const struct curltime *pnow)
{
  if(!data->set.low_speed_time || !data->set.low_speed_limit ||
     Curl_xfer_recv_is_paused(data) || Curl_xfer_send_is_paused(data))
    /* A paused transfer is not qualified for speed checks */
    return CURLE_OK;

  if(data->progress.current_speed >= 0) {
    if(data->progress.current_speed < data->set.low_speed_limit) {
      if(!data->state.keeps_speed.tv_sec)
        /* under the limit at this moment */
        data->state.keeps_speed = *pnow;
      else {
        /* how long has it been under the limit */
        timediff_t howlong =
          curlx_ptimediff_ms(pnow, &data->state.keeps_speed);

        if(howlong >= data->set.low_speed_time * 1000) {
          /* too long */
          failf(data, "Operation too slow. Less than %" FMT_OFF_T
                " bytes/sec transferred the last %u seconds",
                data->set.low_speed_limit, data->set.low_speed_time);
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
    }
    else
      /* faster right now */
      data->state.keeps_speed.tv_sec = 0;
  }

  /* since low speed limit is enabled, set the expire timer to make this
     connection's speed get checked again in a second */
  Curl_expire_set(data, EXPIRE_SPEEDCHECK, 1000, pnow);

  return CURLE_OK;
}

/**
 * @brief Fetch a fresh current time and cache it in the handle.
 *
 * @param[in,out] data  Easy handle whose progress.now is updated.
 * @return Pointer to data->progress.now.
 *
 * @warning The pointer refers to storage inside @p data and is overwritten
 *          by the next call, so copy the value if it must be kept.
 */
const struct curltime *Curl_pgrs_now(struct Curl_easy *data)
{
  curlx_pnow(&data->progress.now);
  return &data->progress.now;
}

/**
 * @brief Finish progress reporting for a completed transfer.
 *
 * Forces a final progress update (the meter and callbacks are invoked even
 * if the last one was recent) and, when the built-in meter is in use,
 * terminates its output line with a newline.
 *
 * Original design notes from the "proposed interface" of 9 Feb 2000:
 * pgrsStartNow() sets the start time, pgrsSetDownloadSize() and
 * pgrsSetUploadSize() record the expected sizes, the two counters track the
 * amount transferred, pgrsUpdate() shows progress and pgrsDone() marks the
 * transfer complete.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     pnow  Current time, not NULL.
 * @return 0 on success, otherwise the non-zero CURLcode produced by the
 *         forced update (for instance CURLE_ABORTED_BY_CALLBACK).
 * @see Curl_pgrsUpdateX()
 */
int Curl_pgrsDone(struct Curl_easy *data, const struct curltime *pnow)
{
  int rc;
  data->progress.delta.lastshow_us = -1;
  rc = Curl_pgrsUpdateX(data, pnow); /* the final (forced) update */
  if(rc)
    return rc;

  if(!data->progress.hide && !data->progress.callback)
    /* only output if we do not use a progress callback and we are not
     * hidden */
    curl_mfprintf(data->set.err, "\n");

  return 0;
}

/**
 * @brief Reset all per-transfer counters, sizes and speed records.
 *
 * Zeroes the upload and download counters, marks both sizes as unknown,
 * drops the speed history and restarts the low-speed measurement. The
 * timers and start time are not touched, see Curl_pgrsStart().
 *
 * @param[in,out] data  Easy handle.
 * @post Both sizes are unknown and progress.deliver is 0.
 */
void Curl_pgrsReset(struct Curl_easy *data)
{
  Curl_pgrsSetUploadCounter(data, 0);
  data->progress.dl.cur_size = 0;
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);
  data->progress.speeder_c = 0; /* reset speed records */
  data->progress.deliver = 0;
  pgrs_speedinit(data);
}

/**
 * @brief Mark both the upload and download size as unknown.
 *
 * @param[in,out] data  Easy handle.
 * @see Curl_pgrsSetDownloadSize()
 * @see Curl_pgrsSetUploadSize()
 */
void Curl_pgrsResetTransferSizes(struct Curl_easy *data)
{
  Curl_pgrsSetDownloadSize(data, -1);
  Curl_pgrsSetUploadSize(data, -1);
}

/**
 * @brief Notify progress tracking that receiving is paused or resumed.
 *
 * On resume the speed records and the low-speed measurement are reset so
 * the time spent paused is not counted as being slow.
 *
 * @param[in,out] data    Easy handle.
 * @param[in]     enable  TRUE when pausing, FALSE when unpausing.
 */
void Curl_pgrsRecvPause(struct Curl_easy *data, bool enable)
{
  if(!enable) {
    data->progress.speeder_c = 0; /* reset speed records */
    pgrs_speedinit(data); /* reset low speed measurements */
  }
}

/**
 * @brief Notify progress tracking that sending is paused or resumed.
 *
 * Counterpart of Curl_pgrsRecvPause() for the upload direction.
 *
 * @param[in,out] data    Easy handle.
 * @param[in]     enable  TRUE when pausing, FALSE when unpausing.
 */
void Curl_pgrsSendPause(struct Curl_easy *data, bool enable)
{
  if(!enable) {
    data->progress.speeder_c = 0; /* reset speed records */
    pgrs_speedinit(data); /* reset low speed measurements */
  }
}

#ifdef CURLVERBOSE
/** Human readable timer names, indexed by timerid, for verbose tracing. */
static const char * const pgrs_timer_names[] = {
  "PGRS-NONE",
  "PGRS-STARTOP",
  "PGRS-STARTSINGLE",
  "PGRS-POSTQUEUE",
  "PGRS-NAMELOOKUP",
  "PGRS-CONNECT",
  "PGRS-APPCONNECT",
  "PGRS-PRETRANSFER",
  "PGRS-STARTTRANSFER",
  "PGRS-POSTRANSFER",
  "PGRS-REDIRECT",
};

/**
 * @brief Map a timer id to its trace name.
 *
 * @param[in] timer  Timer identifier.
 * @return The name of the timer, or "?" when @p timer is out of range. The
 *         string is static and must not be freed.
 * @internal
 */
static const char *pgrs_timer_name(timerid timer)
{
  if((size_t)timer < CURL_ARRAYSIZE(pgrs_timer_names))
    return pgrs_timer_names[(size_t)timer];
  return "?";
}
#endif /* CURLVERBOSE */

/**
 * @brief Store a timestamp for the given timer label.
 *
 * Most timers accumulate the time elapsed since the start of the current
 * single transfer into data->progress.total (at least 1 microsecond is
 * always added so that a timer that fired is never reported as zero).
 * TIMER_STARTOP, TIMER_STARTSINGLE and TIMER_REDIRECT record start offsets
 * instead, TIMER_POSTQUEUE accumulates queue time over all redirects and
 * TIMER_STARTTRANSFER is only recorded once per (redirected) transfer.
 *
 * @param[in,out] data       Easy handle.
 * @param[in]     timer      Which timer to store. TIMER_NONE and unknown
 *                           values are ignored.
 * @param[in]     timestamp  The time to record, by value.
 * @see Curl_pgrsTime()
 */
void Curl_pgrsTimeWas(struct Curl_easy *data, timerid timer,
                      struct curltime timestamp)
{
  timediff_t *delta = NULL;

  switch(timer) {
  default:
  case TIMER_NONE:
    /* mistake filter */
    break;
  case TIMER_STARTOP:
    /* This is set at the start of a transfer */
    data->progress.delta.startop_us =
      curlx_ptimediff_us(&timestamp, &data->progress.start);
    data->progress.delta.startqueue_us = data->progress.delta.startop_us;
    break;
  case TIMER_STARTSINGLE:
    /* This is set at the start of each single transfer */
    data->progress.delta.startsingle_us =
      curlx_ptimediff_us(&timestamp, &data->progress.start);
    data->progress.startransfer_added = FALSE;
    break;
  case TIMER_POSTQUEUE:
    /* Queue time is accumulative from all involved redirects */
    data->progress.total.queued_us +=
      curlx_ptimediff_us(&timestamp, &data->progress.start) -
      data->progress.delta.startqueue_us;
    break;
  case TIMER_NAMELOOKUP:
    delta = &data->progress.total.nslookup_us;
    break;
  case TIMER_CONNECT:
    delta = &data->progress.total.connect_us;
    break;
  case TIMER_APPCONNECT:
    delta = &data->progress.total.appconnect_us;
    break;
  case TIMER_PRETRANSFER:
    delta = &data->progress.total.pretransfer_us;
    break;
  case TIMER_STARTTRANSFER:
    /* prevent updating t_starttransfer unless:
     *   1. this is the first time we are setting t_starttransfer
     *   2. a redirect has occurred since the last time t_starttransfer was set
     * This prevents repeated invocations of the function from incorrectly
     * changing the t_starttransfer time.
     */
    if(data->progress.startransfer_added) {
      CURL_TRC_M(data, "[%s] ignored", pgrs_timer_name(timer));
      return;
    }
    data->progress.startransfer_added = TRUE;
    delta = &data->progress.total.starttransfer_us;
    break;
  case TIMER_POSTRANSFER:
    delta = &data->progress.total.posttransfer_us;
    break;
  case TIMER_REDIRECT:
    data->progress.delta.startredirect_us =
      curlx_ptimediff_us(&timestamp, &data->progress.start);
    /* transfer starts queueing again */
    data->progress.delta.startqueue_us =
      data->progress.delta.startredirect_us;
    break;
  }
  if(delta) {
    timediff_t us = curlx_ptimediff_us(&timestamp, &data->progress.start) -
                    data->progress.delta.startsingle_us;
    if(us < 1)
      us = 1; /* make sure at least one microsecond passed */
    *delta += us;
    CURL_TRC_M(data, "[%s] added %" FMT_TIMEDIFF_T "us",
               pgrs_timer_name(timer), us);
  }
  else
    CURL_TRC_M(data, "[%s] set", pgrs_timer_name(timer));
}

/**
 * @brief Store the current time at the given timer label.
 *
 * Fetches a fresh "now" via Curl_pgrs_now() and forwards it to
 * Curl_pgrsTimeWas().
 *
 * @param[in,out] data   Easy handle.
 * @param[in]     timer  Which timer to store.
 * @see Curl_pgrsTimeWas()
 * @unittest 1399
 */
void Curl_pgrsTime(struct Curl_easy *data, timerid timer)
{
  Curl_pgrsTimeWas(data, timer, *Curl_pgrs_now(data));
}

/**
 * @brief Start progress tracking for a new transfer.
 *
 * Records the start time, clears the delta and total timers, zeroes the
 * counters and flags both sizes as unknown.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     pnow  Start time to use, or NULL to fetch the current time.
 */
void Curl_pgrsStart(struct Curl_easy *data, const struct curltime *pnow)
{
  struct Progress *p = &data->progress;

  if(!pnow)
    pnow = Curl_pgrs_now(data);
  p->speeder_c = 0; /* reset the progress meter display */
  p->start = *pnow;
  memset(&p->delta, 0, sizeof(p->delta));
  memset(&p->total, 0, sizeof(p->total));
  p->startransfer_added = FALSE;
  p->dl.cur_size = 0;
  p->ul.cur_size = 0;
  /* the sizes are unknown at start */
  p->dl_size_known = FALSE;
  p->ul_size_known = FALSE;
}

/**
 * @brief Check that delivering more bytes respects CURLOPT_MAXFILESIZE.
 *
 * @param[in] data   Easy handle.
 * @param[in] delta  Number of bytes about to be delivered to the
 *                   application.
 * @return CURLE_OK if delivery is allowed or no limit is set.
 * @return CURLE_FILESIZE_EXCEEDED if the total delivered would exceed the
 *         configured maximum file size.
 * @see Curl_pgrs_deliver_inc()
 */
CURLcode Curl_pgrs_deliver_check(struct Curl_easy *data, size_t delta)
{
  if(data->set.max_filesize &&
     ((curl_off_t)delta > data->set.max_filesize - data->progress.deliver)) {
    failf(data, "Would have exceeded max file size");
    return CURLE_FILESIZE_EXCEEDED;
  }
  return CURLE_OK;
}

/**
 * @brief Count bytes delivered to the application.
 *
 * In compressed transfers this can differ from the amount downloaded.
 *
 * @param[in,out] data   Easy handle.
 * @param[in]     delta  Number of bytes delivered.
 */
void Curl_pgrs_deliver_inc(struct Curl_easy *data, size_t delta)
{
  data->progress.deliver += delta;
}

/**
 * @brief Count downloaded bytes and charge them to the download rate limit.
 *
 * @param[in,out] data   Easy handle.
 * @param[in]     delta  Number of bytes received; 0 is a no-op.
 */
void Curl_pgrs_download_inc(struct Curl_easy *data, size_t delta)
{
  if(delta) {
    data->progress.dl.cur_size += delta;
    Curl_rlimit_drain(&data->progress.dl.rlimit, delta, NULL);
  }
}

/**
 * @brief Count uploaded bytes and charge them to the upload rate limit.
 *
 * @param[in,out] data   Easy handle.
 * @param[in]     delta  Number of bytes sent; 0 is a no-op.
 */
void Curl_pgrs_upload_inc(struct Curl_easy *data, size_t delta)
{
  if(delta) {
    data->progress.ul.cur_size += delta;
    Curl_rlimit_drain(&data->progress.ul.rlimit, delta, NULL);
  }
}

/**
 * @brief Set the number of uploaded bytes so far.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     size  New upload counter value.
 */
void Curl_pgrsSetUploadCounter(struct Curl_easy *data, curl_off_t size)
{
  data->progress.ul.cur_size = size;
}

/**
 * @brief Set the expected total download size.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     size  Expected size in bytes, or a negative value to mark
 *                      the size as unknown (stored as 0 with the known
 *                      flag cleared).
 */
void Curl_pgrsSetDownloadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.dl.total_size = size;
    data->progress.dl_size_known = TRUE;
  }
  else {
    data->progress.dl.total_size = 0;
    data->progress.dl_size_known = FALSE;
  }
}

/**
 * @brief Set the expected total upload size.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     size  Expected size in bytes, or a negative value to mark
 *                      the size as unknown.
 */
void Curl_pgrsSetUploadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.ul.total_size = size;
    data->progress.ul_size_known = TRUE;
  }
  else {
    data->progress.ul.total_size = 0;
    data->progress.ul_size_known = FALSE;
  }
}

/**
 * @brief Remember how many bytes were sent as TLS early data.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     sent  Number of early data bytes sent.
 */
void Curl_pgrsEarlyData(struct Curl_easy *data, curl_off_t sent)
{
  data->progress.earlydata_sent = sent;
}

/**
 * @brief Compute an average speed in bytes per second.
 *
 * Avoids integer overflow of size * 1000000: when the product would not fit
 * it divides first, and saturates at CURL_OFF_T_MAX when even that is not
 * possible.
 *
 * @param[in] size  Number of bytes transferred.
 * @param[in] us    Elapsed time in microseconds; values < 1 are treated as
 *                  "instant" and yield size * 1000000.
 * @return Average speed in bytes per second.
 * @internal
 */
static curl_off_t trspeed(curl_off_t size, /* number of bytes */
                          curl_off_t us)   /* microseconds */
{
  if(us < 1)
    return size * 1000000;
  else if(size < CURL_OFF_T_MAX / 1000000)
    return (size * 1000000) / us;
  else if(us >= 1000000)
    return size / (us / 1000000);
  else
    return CURL_OFF_T_MAX;
}

/**
 * @brief Update speeds and the history of speed records.
 *
 * Computes the overall average speeds and the "current" speed, which is
 * measured over a sliding window of up to CURL_SPEED_RECORDS one-second
 * records. A new record is only created when at least a second has passed,
 * so frequent calls do not ruin the history. When the transfer is done and
 * no current speed exists yet, the last record is updated instead.
 *
 * @param[in,out] data  Easy handle whose progress fields are updated.
 * @param[in]     pnow  Current time, not NULL.
 * @return TRUE if it is time to show the progress meter (at most once a
 *         second, always for the first call and when the transfer is done),
 *         FALSE otherwise.
 * @internal
 */
static bool progress_calc(struct Curl_easy *data,
                          const struct curltime *pnow)
{
  struct Progress * const p = &data->progress;
  int i_next, i_oldest, i_latest;
  timediff_t duration_us, elapsed_us;
  curl_off_t amount;

  /* The time spent so far (from the start) in microseconds */
  elapsed_us = curlx_ptimediff_us(pnow, &p->start);
  p->total.spent_us = elapsed_us;
  p->dl.speed = trspeed(p->dl.cur_size, p->total.spent_us);
  p->ul.speed = trspeed(p->ul.cur_size, p->total.spent_us);

  if(!p->speeder_c) { /* no previous record exists */
    p->speed_amount[0] = p->dl.cur_size + p->ul.cur_size;
    p->speed_time[0] = elapsed_us;
    p->speeder_c++;
    /* use the overall average at the start */
    p->current_speed = p->ul.speed + p->dl.speed;
    p->delta.lastshow_us = elapsed_us;
    return TRUE;
  }
  /* We have at least one record now. Where to put the next and
   * where is the latest one? */
  i_next = p->speeder_c % CURL_SPEED_RECORDS;
  i_latest = (i_next > 0) ? (i_next - 1) : (CURL_SPEED_RECORDS - 1);

  /* Make a new record only when some time has passed.
   * Too frequent calls otherwise ruin the history. */
  if((elapsed_us - p->speed_time[i_latest]) >= (1000 * 1000)) {
    p->speeder_c++;
    i_latest = i_next;
    p->speed_amount[i_latest] = p->dl.cur_size + p->ul.cur_size;
    p->speed_time[i_latest] = elapsed_us;
  }
  else if(data->req.done) {
    /* When a transfer is done, and we did not have a current speed
     * already, update the last record. Otherwise, stay at the speed
     * we have. The last chunk of data, when rate limiting, would increase
     * reported speed since it no longer measures a full second. */
    if(!p->current_speed) {
      p->speed_amount[i_latest] = p->dl.cur_size + p->ul.cur_size;
      p->speed_time[i_latest] = elapsed_us;
    }
  }
  else {
    /* transfer ongoing, wait for more time to pass. */
    return FALSE;
  }

  i_oldest = (p->speeder_c < CURL_SPEED_RECORDS) ? 0 :
             ((i_latest + 1) % CURL_SPEED_RECORDS);

  /* How much we transferred between oldest and current records */
  amount = p->speed_amount[i_latest] - p->speed_amount[i_oldest];
  /* How long this took */
  duration_us = p->speed_time[i_latest] - p->speed_time[i_oldest];
  if(duration_us <= 0)
    duration_us = 1;

  if(amount > (CURL_OFF_T_MAX / 1000000)) {
    /* the 'amount' value is bigger than would fit in 64 bits if
       multiplied with 1000000, so we use the double math for this */
    p->current_speed =
      (curl_off_t)(((double)amount * 1000000.0) / (double)duration_us);
  }
  else {
    p->current_speed = amount * 1000000 / duration_us;
  }

  if((p->delta.lastshow_us >= 0) && !data->req.done &&
     ((elapsed_us - p->delta.lastshow_us) < (1000 * 1000)))
    return FALSE;
  p->delta.lastshow_us = elapsed_us;
  return TRUE;
}

#ifndef CURL_DISABLE_PROGRESS_METER

/** Time and completion estimate for one transfer direction. */
struct pgrs_estimate {
  /** Estimated total duration in seconds, 0 if unknown. */
  curl_off_t secs;
  /** Estimated completion in percent, 0 if unknown. */
  curl_off_t percent;
};

/**
 * @brief Compute a percentage without overflowing curl_off_t.
 *
 * @param[in] total  Total size; 0 or negative gives 0.
 * @param[in] cur    Amount transferred so far.
 * @return @p cur as a percentage of @p total (not clamped to 100).
 * @internal
 */
static curl_off_t pgrs_est_percent(curl_off_t total, curl_off_t cur)
{
  if(total > 10000)
    return cur / (total / 100);
  else if(total > 0)
    return (cur * 100) / total;
  return 0;
}

/**
 * @brief Estimate duration and completion for one direction.
 *
 * The estimate is based on the average speed so far and is only produced
 * when the total size is known and the speed is positive; otherwise both
 * fields are set to 0.
 *
 * @param[in]  d            Per-direction progress data.
 * @param[in]  total_known  Whether d->total_size is valid.
 * @param[out] est          Receives the estimate.
 * @internal
 */
static void pgrs_estimates(struct pgrs_dir *d,
                           bool total_known,
                           struct pgrs_estimate *est)
{
  est->secs = 0;
  est->percent = 0;
  if(total_known && (d->speed > 0)) {
    est->secs = d->total_size / d->speed;
    est->percent = pgrs_est_percent(d->total_size, d->cur_size);
  }
}

/**
 * @brief Print the classic curl progress meter line to data->set.err.
 *
 * On the first call the two-line column header is printed (preceded by a
 * resume notice when applicable). Each call then rewrites the status line
 * with percentages, sizes, average and current speeds, and total, spent
 * and remaining time, then flushes the stream. Combined totals are capped
 * at CURL_OFF_T_MAX on overflow.
 *
 * @param[in,out] data  Easy handle; progress.headers_out is set.
 * @note Compiled out (macro expands to a no-op statement) when
 *       CURL_DISABLE_PROGRESS_METER is defined.
 * @internal
 */
static void progress_meter(struct Curl_easy *data)
{
  struct Progress *p = &data->progress;
  char max6[6][7];
  struct pgrs_estimate dl_estm;
  struct pgrs_estimate ul_estm;
  struct pgrs_estimate total_estm;
  curl_off_t total_cur_size;
  curl_off_t total_expected_size;
  curl_off_t dl_size;
  char time_left[8];
  char time_total[8];
  char time_spent[8];
  curl_off_t cur_secs = (curl_off_t)p->total.spent_us / 1000000;

  if(!p->headers_out) {
    if(data->state.resume_from) {
      curl_mfprintf(data->set.err,
                    "** Resuming transfer from byte position %" FMT_OFF_T "\n",
                    data->state.resume_from);
    }
    curl_mfprintf(data->set.err,
                  "  %% Total    %% Received %% Xferd  Average Speed  "
                  "Time    Time    Time   Current\n"
                  "                                 Dload  Upload  "
                  "Total   Spent   Left   Speed\n");
    p->headers_out = TRUE; /* headers are shown */
  }

  /* Figure out the estimated time of arrival for upload and download */
  pgrs_estimates(&p->ul, (bool)p->ul_size_known, &ul_estm);
  pgrs_estimates(&p->dl, (bool)p->dl_size_known, &dl_estm);

  /* Since both happen at the same time, total expected duration is max. */
  total_estm.secs = CURLMAX(ul_estm.secs, dl_estm.secs);
  /* create the three time strings */
  time2str(time_left, sizeof(time_left),
           total_estm.secs > 0 ? (total_estm.secs - cur_secs) : 0);
  time2str(time_total, sizeof(time_total), total_estm.secs);
  time2str(time_spent, sizeof(time_spent), cur_secs);

  /* Get the total amount of data expected to get transferred */
  total_expected_size = p->ul_size_known ? p->ul.total_size : p->ul.cur_size;

  dl_size = p->dl_size_known ? p->dl.total_size : p->dl.cur_size;

  /* integer overflow check */
  if((CURL_OFF_T_MAX - total_expected_size) < dl_size)
    total_expected_size = CURL_OFF_T_MAX; /* capped */
  else
    total_expected_size += dl_size;

  /* We have transferred this much so far */
  total_cur_size = p->dl.cur_size + p->ul.cur_size;

  /* Get the percentage of data transferred so far */
  total_estm.percent = pgrs_est_percent(total_expected_size, total_cur_size);

  curl_mfprintf(data->set.err,
                "\r"
                "%3" FMT_OFF_T " %s "
                "%3" FMT_OFF_T " %s "
                "%3" FMT_OFF_T " %s %s %s %s %s %s %s",
                total_estm.percent, /* 3 letters */    /* total % */
                max6out(total_expected_size, max6[2],
                        sizeof(max6[2])),              /* total size */
                dl_estm.percent, /* 3 letters */       /* rcvd % */
                max6out(p->dl.cur_size, max6[0],
                        sizeof(max6[0])),              /* rcvd size */
                ul_estm.percent, /* 3 letters */       /* xfer % */
                max6out(p->ul.cur_size, max6[1],
                        sizeof(max6[1])),              /* xfer size */
                max6out(p->dl.speed, max6[3],
                        sizeof(max6[3])),              /* avrg dl speed */
                max6out(p->ul.speed, max6[4],
                        sizeof(max6[4])),              /* avrg ul speed */
                time_total,    /* 7 letters */         /* total time */
                time_spent,    /* 7 letters */         /* time spent */
                time_left,     /* 7 letters */         /* time left */
                max6out(p->current_speed, max6[5],
                        sizeof(max6[5]))               /* current speed */
    );

  /* we flush the output stream to make it appear as soon as possible */
  fflush(data->set.err);
}
#else /* CURL_DISABLE_PROGRESS_METER */
/** No-op replacement when the progress meter is disabled at build time. */
#define progress_meter(x) Curl_nop_stmt
#endif

/**
 * @brief Invoke the progress callback and optionally the progress meter.
 *
 * Nothing is done if progress is hidden. The extended callback
 * (xferinfo) takes precedence over the deprecated one. A non-zero return
 * from the callback other than CURL_PROGRESSFUNC_CONTINUE aborts the
 * transfer; a zero return from a non-CONTINUE value (such as a callback
 * that handles drawing itself) suppresses the built-in meter this round.
 *
 * @param[in,out] data          Easy handle.
 * @param[in]     showprogress  TRUE if the built-in meter should be drawn.
 * @return CURLE_OK on success.
 * @return CURLE_ABORTED_BY_CALLBACK if the application callback returned a
 *         non-zero value.
 * @internal
 */
static CURLcode pgrsupdate(struct Curl_easy *data, bool showprogress)
{
  if(!data->progress.hide) {
    int rc;
    if(data->set.fxferinfo) {
      /* There is a callback set, call that */
      struct Curl_mapi_guard guard;
      CURL_CBAPI_START(&guard, data, easy_fxferinfo);
      rc = data->set.fxferinfo(data->set.progress_client,
                               data->progress.dl.total_size,
                               data->progress.dl.cur_size,
                               data->progress.ul.total_size,
                               data->progress.ul.cur_size);
      CURL_CBAPI_END(&guard);
      if(rc != CURL_PROGRESSFUNC_CONTINUE) {
        if(rc) {
          failf(data, "Callback aborted");
          return CURLE_ABORTED_BY_CALLBACK;
        }
        return CURLE_OK;
      }
    }
    else if(data->set.fprogress) {
      /* The older deprecated callback is set, call that */
      struct Curl_mapi_guard guard;
      CURL_CBAPI_START(&guard, data, easy_fprogress);
      rc = data->set.fprogress(data->set.progress_client,
                               (double)data->progress.dl.total_size,
                               (double)data->progress.dl.cur_size,
                               (double)data->progress.ul.total_size,
                               (double)data->progress.ul.cur_size);
      CURL_CBAPI_END(&guard);
      if(rc != CURL_PROGRESSFUNC_CONTINUE) {
        if(rc) {
          failf(data, "Callback aborted");
          return CURLE_ABORTED_BY_CALLBACK;
        }
        return CURLE_OK;
      }
    }

    if(showprogress)
      progress_meter(data);
  }

  return CURLE_OK;
}

/**
 * @brief Recalculate progress and report it.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     pnow  Current time, not NULL.
 * @return CURLE_OK or CURLE_ABORTED_BY_CALLBACK, see pgrsupdate().
 * @internal
 */
static CURLcode pgrs_update(struct Curl_easy *data,
                            const struct curltime *pnow)
{
  bool showprogress = progress_calc(data, pnow);
  return pgrsupdate(data, showprogress);
}

/**
 * @brief Update progress using a freshly fetched current time.
 *
 * @param[in,out] data  Easy handle.
 * @return CURLE_OK, or CURLE_ABORTED_BY_CALLBACK if the progress callback
 *         asked to stop.
 */
CURLcode Curl_pgrsUpdate(struct Curl_easy *data)
{
  return pgrs_update(data, Curl_pgrs_now(data));
}

/**
 * @brief Update progress using a caller supplied time.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     pnow  Current time, not NULL.
 * @return CURLE_OK, or CURLE_ABORTED_BY_CALLBACK if the progress callback
 *         asked to stop.
 */
CURLcode Curl_pgrsUpdateX(struct Curl_easy *data,
                          const struct curltime *pnow)
{
  return pgrs_update(data, pnow);
}

/**
 * @brief Update progress and run the low-speed check.
 *
 * The speed check is skipped once the request is done.
 *
 * @param[in,out] data  Easy handle.
 * @param[in]     pnow  Current time, not NULL.
 * @return CURLE_OK, CURLE_ABORTED_BY_CALLBACK from the update, or
 *         CURLE_OPERATION_TIMEDOUT from the speed check.
 */
CURLcode Curl_pgrsCheckX(struct Curl_easy *data,
                         const struct curltime *pnow)
{
  CURLcode result;

  result = pgrs_update(data, pnow);
  if(!result && !data->req.done)
    result = pgrs_speedcheck(data, pnow);
  return result;
}

/**
 * @brief Like Curl_pgrsCheckX() with a freshly fetched current time.
 *
 * @param[in,out] data  Easy handle.
 * @return Same values as Curl_pgrsCheckX().
 */
CURLcode Curl_pgrsCheck(struct Curl_easy *data)
{
  return Curl_pgrsCheckX(data, Curl_pgrs_now(data));
}

/**
 * @brief Update all progress values without meter or callbacks.
 *
 * @param[in,out] data  Easy handle.
 */
void Curl_pgrsUpdate_nometer(struct Curl_easy *data)
{
  (void)progress_calc(data, Curl_pgrs_now(data));
}

/**
 * @brief Finalize the total time spent for a finished transfer.
 *
 * @param[in,out] data  Easy handle; progress.total.spent_us is set.
 */
void Curl_pgrsCompleted(struct Curl_easy *data)
{
  struct Progress * const p = &data->progress;
  p->total.spent_us = curlx_ptimediff_us(Curl_pgrs_now(data), &p->start);
}

/**
 * @brief Milliseconds elapsed since a start timer.
 *
 * @param[in,out] data   Easy handle.
 * @param[in]     pnow   Current time, or NULL to fetch it.
 * @param[in]     timer  Either TIMER_STARTOP or TIMER_STARTSINGLE; any
 *                       other value is a programming error (asserts in
 *                       debug builds).
 * @return Elapsed milliseconds, or 0 for an unsupported @p timer.
 */
timediff_t Curl_pgrs_since_ms(struct Curl_easy *data,
                              const struct curltime *pnow,
                              timerid timer)
{
  if(!pnow)
    pnow = Curl_pgrs_now(data);
  switch(timer) {
  case TIMER_STARTOP:
    return (curlx_ptimediff_us(pnow, &data->progress.start) -
            data->progress.delta.startop_us) / 1000;
  case TIMER_STARTSINGLE:
    return (curlx_ptimediff_us(pnow, &data->progress.start) -
            data->progress.delta.startsingle_us) / 1000;
  default:
    DEBUGASSERT(0);
    return 0;
  }
}
/** @} */
