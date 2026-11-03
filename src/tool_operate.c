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
 * @brief Core of the curl tool: sets up and runs all transfers.
 *
 * This file implements operate(), which parses .curlrc and the command line,
 * creates the share object, builds one libcurl easy handle per URL (including
 * URL globbing, upload files, output files, ETag files and retries) and drives
 * them either serially or in parallel through the multi interface.
 *
 * @note Transfers are tracked in a doubly linked list of per_transfer nodes.
 * @warning The list and the global state are not protected by locks; the tool
 *          uses them from a single thread only.
 * @see tool_main.c, tool_cfgable.h, tool_getparam.c
 */
#include "tool_setup.h"

#include "curlx/nonblock.h" /* for curlx_nonblock() */

#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#ifdef __VMS
#  include <fabdef.h>
#endif

#ifdef __AMIGA__
#  include <proto/dos.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_UV_H
/* this is for libuv-enabled debug builds only */
#include <uv.h>
#endif

#include "tool_cfgable.h"
#include "tool_cb_hdr.h"
#include "tool_cb_prg.h"
#include "tool_cb_wrt.h"
#include "tool_dirhie.h"
#include "tool_doswin.h"
#include "tool_easysrc.h"
#include "tool_filetime.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_libinfo.h"
#include "tool_main.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_operhlp.h"
#include "tool_paramhlp.h"
#include "tool_parsecfg.h"
#include "tool_setopt.h"
#include "tool_ssls.h"
#include "tool_urlglob.h"
#include "tool_util.h"
#include "tool_writeout.h"
#include "tool_xattr.h"
#include "tool_vms.h"
#include "tool_help.h"
#include "tool_hugehelp.h"
#include "tool_progress.h"
#include "tool_ipfs.h"
#include "config2setopts.h"
#include "var.h"

#ifdef DEBUGBUILD
/* libcurl's debug-only curl_easy_perform_ev() */
CURL_EXTERN CURLcode curl_easy_perform_ev(CURL *easy);
#endif

/**
 * @brief Hint printed after a certificate verification failure.
 *
 * Points the user to the curl documentation about SSL CA certificates.
 * Used when a transfer fails with a peer verification error.
 */
#define CURL_CA_CERT_ERRORMSG                                              \
  "More details here: https://curl.se/docs/sslcerts.html\n\n"              \
  "curl failed to verify the legitimacy of the server and therefore "      \
  "could not\nestablish a secure connection to it. To learn more about "   \
  "this situation and\nhow to fix it, please visit the webpage mentioned " \
  "above.\n"

/**
 * @brief Forward declaration of create_transfer().
 * @see create_transfer()
 */
static CURLcode create_transfer(CURLSH *share,
                                bool *added,
                                bool *skipped);

/**
 * @internal
 * @brief Tell whether a libcurl result code must abort all transfers.
 *
 * A fatal error is one that points at a broken setup or resource
 * exhaustion rather than at a single failed transfer.
 *
 * @param[in] code Result code of a finished transfer.
 * @return TRUE for CURLE_FAILED_INIT, CURLE_OUT_OF_MEMORY,
 *         CURLE_UNKNOWN_OPTION and CURLE_BAD_FUNCTION_ARGUMENT;
 *         FALSE for any other value, including CURLE_OK.
 */
static bool is_fatal_error(CURLcode code)
{
  switch(code) {
  case CURLE_FAILED_INIT:
  case CURLE_OUT_OF_MEMORY:
  case CURLE_UNKNOWN_OPTION:
  case CURLE_BAD_FUNCTION_ARGUMENT:
    /* critical error */
    return TRUE;
  default:
    break;
  }

  /* no error or not critical */
  return FALSE;
}

/**
 * @internal
 * @brief Check if a given string is a PKCS#11 URI.
 *
 * The match is case-insensitive and only looks at the "pkcs11:" prefix.
 *
 * @param[in] string NUL-terminated string to test, must not be NULL.
 * @return TRUE if the string starts with "pkcs11:", otherwise FALSE.
 */
static bool is_pkcs11_uri(const char *string)
{
  if(curl_strnequal(string, "pkcs11:", 7)) {
    return TRUE;
  }
  else {
    return FALSE;
  }
}

#ifdef __VMS
/**
 * @internal
 * @brief Get the real size of a file on VMS (VMS only).
 *
 * For fixed files, find out the size of the EOF block and adjust.
 * For all others the entire file has to be read in, discarding the
 * contents. Most posted text files are small, and binary files like zlib
 * archives and CD/DVD images should be either a STREAM_LF format or a
 * fixed format.
 *
 * @param[in] name     Path of the file to measure.
 * @param[in] stat_buf  Result of stat() for @p name (currently unused).
 * @return Number of bytes in the file, or 0 if it cannot be opened.
 * @note Reading the file is O(n) in the file size.
 */
static curl_off_t vms_realfilesize(const char *name,
                                   const curlx_struct_stat *stat_buf)
{
  char buffer[8192];
  curl_off_t count;
  int ret_stat;
  FILE *file;

  /* !checksrc! disable FOPENMODE 1 */
  file = curlx_fopen(name, "r"); /* VMS */
  if(!file) {
    return 0;
  }
  count = 0;
  ret_stat = 1;
  while(ret_stat > 0) {
    ret_stat = fread(buffer, 1, sizeof(buffer), file);
    if(ret_stat)
      count += ret_stat;
  }
  curlx_fclose(file);

  return count;
}

/**
 * @internal
 * @brief Check if st_size can be trusted and fix it if not (VMS only).
 *
 * Variable-length record formats (FAB$C_VAR, FAB$C_VFC) report a size that
 * does not match the byte count, so vms_realfilesize() is used for them.
 *
 * @param[in] name     Path of the file.
 * @param[in] stat_buf  Result of stat() for @p name.
 * @return The size in bytes of the file as it will be read.
 * @see vms_realfilesize()
 */
static curl_off_t VmsSpecialSize(const char *name,
                                 const curlx_struct_stat *stat_buf)
{
  switch(stat_buf->st_fab_rfm) {
  case FAB$C_VAR:
  case FAB$C_VFC:
    return vms_realfilesize(name, stat_buf);
  default:
    return stat_buf->st_size;
  }
}
#endif /* __VMS */

/**
 * @brief Head of the global list of transfers (first node).
 * @see add_per_transfer(), del_per_transfer()
 */
struct per_transfer *transfers; /* first node */
/**
 * @internal
 * @brief Tail of the global list of transfers (last node).
 */
static struct per_transfer *transfersl; /* last node */

/* add_per_transfer creates a new 'per_transfer' node in the linked
   list of transfers */
/**
 * @internal
 * @brief Create a new per_transfer node and append it to the list.
 *
 * The node is zero-initialised and linked at the tail of the global
 * transfers list.
 *
 * @param[out] per Receives the new node on success; untouched on failure.
 * @return CURLE_OK on success, CURLE_OUT_OF_MEMORY if allocation failed.
 * @post On success the node is owned by the list and must be released with
 *       del_per_transfer().
 */
static CURLcode add_per_transfer(struct per_transfer **per)
{
  struct per_transfer *p;
  p = curlx_calloc(1, sizeof(struct per_transfer));
  if(!p)
    return CURLE_OUT_OF_MEMORY;
  if(!transfers)
    /* first entry */
    transfersl = transfers = p;
  else {
    /* make the last node point to the new node */
    transfersl->next = p;
    /* make the new node point back to the formerly last node */
    p->prev = transfersl;
    /* move the last node pointer to the new entry */
    transfersl = p;
  }
  *per = p;

  return CURLE_OK;
}

/* Remove the specified transfer from the list (and free it), return the next
   in line */
/**
 * @internal
 * @brief Remove a transfer from the list, free it and return the next one.
 *
 * Releases every resource owned by the node (output file, easy handle,
 * URL strings, header lists and so on).
 *
 * @param[in] per Node to remove; must be a member of the list.
 * @return The node that followed @p per, or NULL if it was the last one.
 * @warning @p per is invalid after the call, do not use it again.
 */
static struct per_transfer *del_per_transfer(struct per_transfer *per)
{
  struct per_transfer *n;
  struct per_transfer *p;
  DEBUGASSERT(transfers);
  DEBUGASSERT(transfersl);
  DEBUGASSERT(per);

  n = per->next;
  p = per->prev;

  if(p)
    p->next = n;
  else
    transfers = n;

  if(n)
    n->prev = p;
  else
    transfersl = p;

  curlx_free(per->uploadfile);
  curlx_free(per->outfile);
  curlx_free(per->url);
  curl_easy_cleanup(per->curl);
  curlx_free(per);

  return n;
}

/**
 * @internal
 * @brief Prepare a transfer right before it starts.
 *
 * Determines the size of the upload file (if any), sets the input size
 * option on the easy handle and records the start time.
 *
 * @param[in,out] per Transfer about to be performed.
 * @return CURLE_OK on success, or the error from setting the upload size.
 * @pre per->curl has been fully configured.
 * @post per->uploadfilesize and per->start are set.
 */
static CURLcode pre_transfer(struct per_transfer *per)
{
  curl_off_t uploadfilesize = -1;
  curlx_struct_stat fileinfo;
  CURLcode result = CURLE_OK;

  if(per->uploadfile && !stdin_upload(per->uploadfile)) {
    /* VMS Note:
     *
     * Reading binary from files can be a problem... Only FIXED, VAR
     * etc WITHOUT implied CC do work. Others need a \n appended to
     * a line
     *
     * - Stat gives a size but this is UNRELIABLE in VMS. E.g.
     * a fixed file with implied CC needs to have a byte added for every
     * record processed, this can be derived from Filesize & recordsize
     * for VARiable record files the records need to be counted!  for
     * every record add 1 for linefeed and subtract 2 for the record
     * header for VARIABLE header files only the bare record data needs
     * to be considered with one appended if implied CC
     */
#ifdef __VMS
    /* Calculate the real upload size for VMS */
    per->infd = -1;
    if(curlx_stat(per->uploadfile, &fileinfo) == 0) {
      fileinfo.st_size = VmsSpecialSize(per->uploadfile, &fileinfo);
      switch(fileinfo.st_fab_rfm) {
      case FAB$C_VAR:
      case FAB$C_VFC:
      case FAB$C_STMCR:
        per->infd = curlx_open(per->uploadfile, O_RDONLY | CURL_O_BINARY);
        break;
      default:
        per->infd = curlx_open(per->uploadfile, O_RDONLY | CURL_O_BINARY,
                               "rfm=stmlf", "ctx=stm");
      }
    }
    if(per->infd == -1)
#else
      per->infd = curlx_open(per->uploadfile, O_RDONLY | CURL_O_BINARY);
    if((per->infd == -1) || curlx_fstat(per->infd, &fileinfo))
#endif
    {
      helpf("cannot open '%s'", per->uploadfile);
      if(per->infd != -1) {
        curlx_close(per->infd);
        per->infd = STDIN_FILENO;
      }
      return CURLE_READ_ERROR;
    }
    per->infdopen = TRUE;

    /* we ignore file size for char/block devices, sockets, etc. */
    if(S_ISREG(fileinfo.st_mode))
      uploadfilesize = fileinfo.st_size;

#ifdef DEBUGBUILD
    /* allow dedicated test cases to override */
    {
      const char *ev = getenv("CURL_UPLOAD_SIZE");
      if(ev) {
        curl_off_t sz;
        curlx_str_number(&ev, &sz, CURL_OFF_T_MAX);
        uploadfilesize = sz;
      }
    }
#endif

    if(uploadfilesize != -1)
      my_setopt_offt(per->curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
  }
  per->uploadfilesize = uploadfilesize;
  per->start = curlx_now();
  return result;
}

/**
 * @brief Free the per-URL state kept in the global State.
 *
 * Releases the URL glob, the current upload file name and the upload file
 * glob. Called when no further transfer can be created from the current
 * operation config.
 *
 * @note Safe to call multiple times.
 * @see single_transfer()
 */
void single_transfer_cleanup(void)
{
  struct State *state = &global->state;
  /* Free list of remaining URLs */
  glob_cleanup(&state->urlglob);
  curlx_safefree(state->uploadfile);
  /* Free list of globbed upload files */
  glob_cleanup(&state->inglob);
}

/**
 * @internal
 * @brief Decide if a failed download may be resumed automatically.
 *
 * Used when retrying a transfer that wrote to a regular output file with
 * @c --continue-at -. The conditions are somewhat pedantic to avoid any
 * risk of data corruption.
 *
 * Specific HTTP limitations (scheme, method, response code, etc) are
 * checked in retrycheck() if this prerequisite check is met.
 *
 * @param[in] config Operation configuration.
 * @param[in] per    Transfer that just ended.
 * @param[in] result Result code of the transfer.
 * @return TRUE if the next attempt can resume where this one stopped.
 * @see retrycheck()
 */
static bool is_outfile_auto_resumable(struct OperationConfig *config,
                                      struct per_transfer *per,
                                      CURLcode result)
{
  struct OutStruct *outs = &per->outs;
  return config->use_resume && config->resume_from_current &&
    config->resume_from >= 0 && outs->init == config->resume_from &&
    outs->bytes > 0 && outs->filename && outs->regular_file && outs->fopened &&
    outs->stream && !ferror(outs->stream) &&
    !config->customrequest && !per->uploadfile &&
    (config->httpreq == TOOL_HTTPREQ_UNSPEC ||
     config->httpreq == TOOL_HTTPREQ_GET) &&
    /* CURLE_WRITE_ERROR could mean outs->bytes is not accurate */
    result != CURLE_WRITE_ERROR && result != CURLE_RANGE_ERROR;
}

/**
 * @internal
 * @brief Reason why a transfer is going to be retried.
 *
 * Indexes the message table in retry_sleep().
 */
enum retryreason {
  RETRY_NO, ///< no retry
  RETRY_ALL_ERRORS, ///< --retry-all-errors
  RETRY_TIMEOUT, ///< timeout or DNS
  RETRY_CONNREFUSED, ///< connection refused
  RETRY_HTTP, ///< HTTP status
  RETRY_FTP ///< FTP 4xx
};

/**
 * @internal
 * @brief Figure out how long to wait until the next retry.
 *
 * Uses exponential backoff unless a fixed delay was requested, then
 * prints the retry message. If the retry budget is exhausted, no retry
 * is scheduled.
 *
 * @param[in]     config Operation configuration (retry delay and limits).
 * @param[in,out] per    Transfer; its retry counters are updated.
 * @param[in]     retry  Reason for the retry, selects the message printed.
 * @param[out]    retryp Set to FALSE if the retry limit was reached.
 * @return Delay in milliseconds before the next attempt.
 * @see retrycheck()
 */
static uint32_t retry_sleep(struct OperationConfig *config,
                            struct per_transfer *per,
                            enum retryreason retry,
                            bool *retryp)
{
  static const char * const m[] = {
    "(retrying all errors)",
    ": timeout",
    ": connection refused",
    ": HTTP error",
    ": FTP error"
  };
  CURL *curl = per->curl;
  uint32_t sleeptime = 0;
  if(RETRY_HTTP == retry) {
    curl_off_t retry_after = 0;
    curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
    if(retry_after) {
      /* make sure it does not overflow */
      if(retry_after > (curl_off_t)(UINT32_MAX / 1000))
        sleeptime = UINT32_MAX;
      else
        sleeptime = (uint32_t)retry_after * 1000U; /* milliseconds */

      /* if adding retry_after seconds to the process would exceed the
         maximum time allowed for retrying, then exit the retries right
         away */
      if(config->retry_maxtime_ms) {
        timediff_t ms = curlx_timediff_ms(curlx_now(), per->retrystart);

        if((CURL_OFF_T_MAX - sleeptime < ms) ||
           (ms + sleeptime > config->retry_maxtime_ms)) {
          warnf("The Retry-After: time would "
                "make this command line exceed the maximum allowed time "
                "for retries.");
          *retryp = FALSE;
          return 0; /* no retry */
        }
      }
    }
  }
  if(!sleeptime && !config->retry_delay_ms) {
    if(!per->retry_sleep)
      per->retry_sleep = RETRY_SLEEP_DEFAULT;
    else
      per->retry_sleep *= 2;
    if(per->retry_sleep > RETRY_SLEEP_MAX)
      per->retry_sleep = RETRY_SLEEP_MAX;
  }
  if(!sleeptime)
    sleeptime = per->retry_sleep;

  warnf("Problem %s. Retrying in %u%s%.*u second%s. "
        "%ld retr%s left.",
        m[retry - 1], sleeptime / 1000,
        (sleeptime % 1000 ? "." : ""),
        (sleeptime % 1000 ? 3 : 0),
        sleeptime % 1000,
        (sleeptime == 1000 ? "" : "s"),
        per->retry_remaining,
        (per->retry_remaining > 1 ? "ies" : "y"));

  return sleeptime;
}

/**
 * @internal
 * @brief Decide whether a finished transfer should be retried.
 *
 * Looks at the result code, the HTTP status and FTP response to match
 * transient conditions (timeouts, DNS failures, refused connections,
 * HTTP 408/429/5xx, FTP 4xx) and the @c --retry options.
 *
 * @param[in]     config  Operation configuration.
 * @param[in,out] per     Transfer that just ended.
 * @param[in]     result  Result of the transfer.
 * @param[out]    retryp  Set to TRUE when the transfer should be retried.
 * @param[out]    delayms Delay before the retry, in milliseconds.
 * @return @p result unchanged, or CURLE_OK when a retry is scheduled.
 * @note When retrying, the output file may be truncated or reopened for
 *       appending depending on is_outfile_auto_resumable().
 */
static CURLcode retrycheck(struct OperationConfig *config,
                           struct per_transfer *per,
                           CURLcode result,
                           bool *retryp,
                           uint32_t *delayms)
{
  CURL *curl = per->curl;
  struct OutStruct *outs = &per->outs;
  enum retryreason reason = RETRY_NO;
  if((result == CURLE_OPERATION_TIMEDOUT) ||
     (result == CURLE_COULDNT_RESOLVE_HOST) ||
     (result == CURLE_COULDNT_RESOLVE_PROXY) ||
     (result == CURLE_FTP_ACCEPT_TIMEOUT))
    /* retry timeout always */
    reason = RETRY_TIMEOUT;
  else if(config->retry_connrefused &&
          (result == CURLE_COULDNT_CONNECT)) {
    long oserrno = 0;
    curl_easy_getinfo(curl, CURLINFO_OS_ERRNO, &oserrno);
    if(SOCKECONNREFUSED == oserrno)
      reason = RETRY_CONNREFUSED;
  }
  else if((result == CURLE_OK) ||
          (config->fail && (result == CURLE_HTTP_RETURNED_ERROR))) {
    /* If it returned OK. _or_ failonerror was enabled and it
       returned due to such an error, check for HTTP transient
       errors to retry on. */
    const char *scheme;
    curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
    scheme = proto_token(scheme);
    if(scheme == proto_http || scheme == proto_https) {
      /* This was HTTP(S) */
      long response = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

      switch(response) {
      case 408: /* Request Timeout */
      case 429: /* Too Many Requests (RFC6585) */
      case 500: /* Internal Server Error */
      case 502: /* Bad Gateway */
      case 503: /* Service Unavailable */
      case 504: /* Gateway Timeout */
      case 522: /* Connection Timed Out (Cloudflare) */
      case 524: /* Proxy Read Timeout (Cloudflare) */
        reason = RETRY_HTTP;
        /*
         * At this point, we have already written data to the output
         * file (or terminal). If we write to a file, we must rewind
         * or close/re-open the file so that the next attempt starts
         * over from the beginning.
         *
         * For the upload case, we might need to start over reading from a
         * previous point if we have uploaded something when this was
         * returned.
         */
        break;
      }
    }
  } /* if CURLE_OK */
  else if(result) {
    const char *scheme;
    long response = 0;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
    scheme = proto_token(scheme);

    if((scheme == proto_ftp || scheme == proto_ftps) && response / 100 == 4)
      /*
       * This is typically when the FTP server only allows a certain
       * amount of users and we are not one of them. All 4xx codes
       * are transient.
       */
      reason = RETRY_FTP;
  }

  if(result && !reason && config->retry_all_errors)
    reason = RETRY_ALL_ERRORS;

  if(reason) {
    bool truncate = TRUE; /* truncate output file */

    /* how long to wait until next attempt */
    uint32_t sleeptime;

    *retryp = TRUE;

    sleeptime = retry_sleep(config, per, reason, retryp);
    if(!*retryp)
      /* no retry */
      return CURLE_OK;
    per->retry_remaining--;

    /* Skip truncation of outfile if auto-resume is enabled for download and
       the partially received data is good. Only for HTTP GET requests in
       limited circumstances. */
    if(is_outfile_auto_resumable(config, per, result)) {
      long response = 0;
      struct curl_header *header = NULL;
      const char *method = NULL, *scheme = NULL;

      curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_METHOD, &method);
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
      curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
      scheme = proto_token(scheme);

      if((scheme == proto_http || scheme == proto_https) &&
         method && !strcmp(method, "GET") &&
         ((response == 206 && config->resume_from) ||
          (response == 200 &&
           !curl_easy_header(curl, "Accept-Ranges", 0,
                             CURLH_HEADER, -1, &header) &&
           !strcmp(header->value, "bytes")))) {

        notef("Keeping %" CURL_FORMAT_CURL_OFF_T " bytes", outs->bytes);
        if(fflush(outs->stream)) {
          errorf("Failed to flush output file stream");
          *retryp = FALSE;
          return CURLE_WRITE_ERROR;
        }
        if(outs->bytes >= CURL_OFF_T_MAX - outs->init) {
          errorf("Exceeded maximum supported file size ("
                 "%" CURL_FORMAT_CURL_OFF_T " + "
                 "%" CURL_FORMAT_CURL_OFF_T ")",
                 outs->init, outs->bytes);
          *retryp = FALSE;
          return CURLE_WRITE_ERROR;
        }
        truncate = FALSE;
        outs->init += outs->bytes;
        per->dlretry += outs->bytes;
        outs->bytes = 0;
        config->resume_from = outs->init;
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, config->resume_from);
      }
    }

    if(truncate && outs->bytes && outs->filename && outs->stream) {
      curlx_struct_stat fileinfo;

      /* The output can be a named pipe or a character device etc that
         cannot be truncated. Only truncate regular files. */
      if(!curlx_fstat(fileno(outs->stream), &fileinfo) &&
         S_ISREG(fileinfo.st_mode)) {
        int rc;
        /* We have written data to an output file, we truncate file */
        fflush(outs->stream);
        notef("Throwing away %" CURL_FORMAT_CURL_OFF_T " bytes", outs->bytes);

        /* truncate file at the position where we started appending */
        if(
#ifdef DEBUGBUILD
           getenv("CURL_DBG_TRUNCATE_FAIL") ||
#endif
           toolx_ftruncate(fileno(outs->stream), outs->init)) {
          /* when truncate fails, we cannot append as then we
             create something strange, bail out */
          errorf("Failed to truncate file");
          *retryp = FALSE;
          return CURLE_WRITE_ERROR;
        }
        /* now seek to the end of the file, the position where we
           truncated the file in a large file-safe way */
        rc = fseek(outs->stream, 0, SEEK_END);

        if(rc) {
          errorf("Failed seeking to end of file");
          *retryp = FALSE;
          return CURLE_WRITE_ERROR;
        }
        outs->bytes = 0; /* clear for next round */
      }
    }
    per->num_retries++;
    *delayms = sleeptime;
    result = CURLE_OK;
  }
  return result;
}

/**
 * @internal
 * @brief Post-process the result of a transfer (error reporting).
 *
 * Maps failures to messages, handles @c --fail-with-body, the certificate
 * hint and the VMS exit status.
 *
 * @param[in,out] per    Transfer that ended.
 * @param[in]     result  Result code from libcurl.
 * @return The (possibly adjusted) result code; CURLE_HTTP_RETURNED_ERROR
 *         when --fail-with-body saw an HTTP status of 400 or above.
 */
static CURLcode post_check_result(struct per_transfer *per, CURLcode result)
{
  struct OperationConfig *config = per->config;

#ifdef __VMS
  if(is_vms_shell()) {
    /* VMS DCL shell behavior */
    if(global->silent && !global->showerror)
      vms_show = VMSSTS_HIDE;
  }
#endif
  if(!config->synthetic_error && result &&
     (!global->silent || global->showerror)) {
    const char *msg = per->errorbuffer;
    curl_mfprintf(tool_stderr, "curl: (%d) %s\n", (int)result,
                  msg[0] ? msg : curl_easy_strerror(result));
    if(result == CURLE_PEER_FAILED_VERIFICATION)
      fputs(CURL_CA_CERT_ERRORMSG, tool_stderr);
  }
  else if(config->fail == FAIL_WITH_BODY) {
    /* if HTTP response >= 400, return error */
    long code = 0;
    curl_easy_getinfo(per->curl, CURLINFO_RESPONSE_CODE, &code);
    if(code >= 400) {
      if(!global->silent || global->showerror)
        curl_mfprintf(tool_stderr,
                      "curl: (%d) The requested URL returned error: %ld\n",
                      CURLE_HTTP_RETURNED_ERROR, code);
      return CURLE_HTTP_RETURNED_ERROR;
    }
  }
  return result;
}

/**
 * @internal
 * @brief Finalise output handling after the transfer.
 *
 * Flushes the output stream, applies remote time and removes partial
 * output on failure when requested.
 *
 * @param[in,out] per    Transfer that ended.
 * @param[in]     result  Result code so far.
 * @return @p result, or CURLE_WRITE_ERROR if flushing failed.
 */
static CURLcode post_output_handling(struct per_transfer *per,
                                     CURLcode result)
{
  struct OutStruct *outs = &per->outs;
  struct OperationConfig *config = per->config;
  CURL *curl = per->curl;
  int rc;

#ifdef _WIN32
  /* Discard incomplete UTF-8 sequence buffered from body */
  memset(outs->utf8seq, 0, sizeof(outs->utf8seq));
#endif

  /* Set file extended attributes */
  if(!result && config->xattr && outs->fopened && outs->stream) {
    rc = fwrite_xattr(curl, per->url, fileno(outs->stream), outs->filename);
    if(rc) {
      char errbuf[STRERROR_LEN];
      warnf("Error setting extended attributes on '%s': %s", outs->filename,
            curlx_strerror(errno, errbuf, sizeof(errbuf)));
    }
  }

  if(!result && !outs->stream && !outs->bytes) {
    /* we have received no data despite the transfer was successful
       ==> force creation of an empty output file (if an output file
       was specified) */
    long cond_unmet = 0L;
    /* do not create (or even overwrite) the file in case we get no
       data because of unmet condition */
    curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &cond_unmet);
    if(!cond_unmet && !tool_create_output_file(outs, config))
      return CURLE_WRITE_ERROR;
    /* write headers buffered while waiting for a -J filename */
    if(outs->stream && per->hdrcbdata.headlist &&
       tool_write_headers(&per->hdrcbdata, outs->stream))
      return CURLE_WRITE_ERROR;
  }

  if(!outs->regular_file && outs->stream && !outs->out_null) {
    /* Dump standard stream buffered data */
    rc = fflush(outs->stream);
    if(!result && rc) {
      /* something went wrong in the writing process */
      errorf("Failed writing body");
      return CURLE_WRITE_ERROR;
    }
  }

  return result;
}

/**
 * @internal
 * @brief Close the output, header and ETag files of a transfer.
 *
 * @param[in,out] per    Transfer that ended.
 * @param[in]     result  Result code so far.
 * @return @p result, or CURLE_WRITE_ERROR if closing a file failed.
 * @post The stream pointers in @p per are no longer valid.
 */
static CURLcode post_close_output(struct per_transfer *per,
                                  CURLcode result)
{
  struct OutStruct *outs = &per->outs;
  struct OperationConfig *config = per->config;
  int rc;

  /* Close the outs file */
  if(outs->fopened && outs->stream) {
    rc = curlx_fclose(outs->stream);
    outs->stream = NULL;
    outs->fopened = FALSE;
    if(!result && rc) {
      /* something went wrong in the writing process */
      result = CURLE_WRITE_ERROR;
      errorf("curl: (%d) Failed writing body", (int)result);
    }
    if(result && config->rm_partial) {
      curlx_struct_stat st;
      if(!curlx_stat(outs->filename, &st) && S_ISREG(st.st_mode)) {
        if(!unlink(outs->filename))
          notef("Removed output file: %s", outs->filename);
        else
          warnf("Failed removing: %s", outs->filename);
      }
      else
        warnf("Skipping removal; not a regular file: %s", outs->filename);
    }
  }

  /* File time can only be set _after_ the file has been closed */
  if(!result && config->remote_time && outs->regular_file && outs->filename) {
    /* Ask libcurl if we got a remote file time */
    curl_off_t filetime = -1;
    curl_easy_getinfo(per->curl, CURLINFO_FILETIME_T, &filetime);
    if(filetime != -1)
      setfiletime(filetime, outs->filename);
  }
  return result;
}

/**
 * @internal
 * @brief Handle everything that happens after a transfer has completed.
 *
 * Runs result checks, decides on retries, closes files, writes the
 * @c --write-out data and the ETag, and applies --remove-on-error.
 *
 * @param[in,out] per    Transfer that ended.
 * @param[in]     result  Result code of the transfer.
 * @param[out]    retryp  Set to TRUE if the transfer must be run again.
 * @param[out]    delay   Retry delay in milliseconds, 0 when no retry.
 * @return The final result code for this transfer.
 * @see retrycheck(), post_check_result()
 */
static CURLcode post_per_transfer(struct per_transfer *per,
                                  CURLcode result,
                                  bool *retryp,
                                  uint32_t *delay) /* milliseconds! */
{
  struct OutStruct *outs = &per->outs;
  struct OperationConfig *config = per->config;

  *retryp = FALSE;
  *delay = 0; /* for no retry, keep it zero */

  if(!per->curl || !config)
    return result;

#ifdef _WIN32
  if(per->uploadfile) {
    if(!strcmp(per->uploadfile, ".") && per->infd > 0) {
#ifndef CURL_WINDOWS_UWP
      sclose(per->infd);
#else
      warnf("Closing per->infd != 0: FD == %d. "
            "This behavior is only supported on desktop Windows", per->infd);
#endif
    }
  }
  else
#endif
    if(per->infdopen)
      curlx_close(per->infd);

  if(!per->skip) {
    result = post_check_result(per, result);
    result = post_output_handling(per, result);

    /* if retry-max-time is non-zero, make sure we have not exceeded the
       time */
    if(per->retry_remaining &&
       (!config->retry_maxtime_ms ||
        (curlx_timediff_ms(curlx_now(), per->retrystart) <
         config->retry_maxtime_ms))) {
      result = retrycheck(config, per, result, retryp, delay);
      if(!result && *retryp)
        return CURLE_OK; /* retry! */
    }

    if((global->progressmode == CURL_PROGRESS_BAR) &&
       per->progressbar.calls)
      /* if the custom progress bar has been displayed, we output a
         newline here */
      fputs("\n", per->progressbar.out);

    result = post_close_output(per, result);
  }
  /* Write the --write-out data before cleanup but after result is final */
  if(config->writeout)
    ourWriteOut(config, per, result);

  /* Close function-local opened file descriptors */
  if(per->heads.fopened && per->heads.stream)
    curlx_fclose(per->heads.stream);

  if(per->heads.alloc_filename)
    curlx_safefree(per->heads.filename);

  if(per->etag_save.fopened && per->etag_save.stream)
    curlx_fclose(per->etag_save.stream);

  if(per->etag_save.alloc_filename)
    curlx_safefree(per->etag_save.filename);

  if(outs->alloc_filename)
    curlx_safefree(outs->filename);
  slist_wc_free_all(per->hdrcbdata.headlist);
  per->hdrcbdata.headlist = NULL;
  return result;
}

/**
 * @internal
 * @brief Pick implicit certificate and key types.
 *
 * A PKCS#11 URI given as certificate or key makes the type "ENG" when no
 * type was set. Does nothing without SSL support.
 *
 * @param[in,out] config Operation configuration.
 * @return CURLE_OK, or CURLE_OUT_OF_MEMORY if a string copy failed.
 */
static CURLcode set_cert_types(struct OperationConfig *config)
{
  if(feature_ssl) {
    /* Check if config->cert is a PKCS#11 URI and set the config->cert_type if
     * necessary */
    if(config->cert && !config->cert_type && is_pkcs11_uri(config->cert)) {
      config->cert_type = curlx_strdup("ENG");
      if(!config->cert_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->key is a PKCS#11 URI and set the config->key_type if
     * necessary */
    if(config->key && !config->key_type && is_pkcs11_uri(config->key)) {
      config->key_type = curlx_strdup("ENG");
      if(!config->key_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->proxy_cert is a PKCS#11 URI and set the
     * config->proxy_type if necessary */
    if(config->proxy_cert && !config->proxy_cert_type &&
       is_pkcs11_uri(config->proxy_cert)) {
      config->proxy_cert_type = curlx_strdup("ENG");
      if(!config->proxy_cert_type)
        return CURLE_OUT_OF_MEMORY;
    }

    /* Check if config->proxy_key is a PKCS#11 URI and set the
     * config->proxy_key_type if necessary */
    if(config->proxy_key && !config->proxy_key_type &&
       is_pkcs11_uri(config->proxy_key)) {
      config->proxy_key_type = curlx_strdup("ENG");
      if(!config->proxy_key_type)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

/**
 * @internal
 * @brief Append a query string to the URL of a transfer.
 *
 * Implements @c --url-query by parsing the URL with the URL API and adding
 * the part to the query.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] per    Transfer whose URL is rewritten.
 * @param[in]     q      Query part to append; may be NULL for no-op.
 * @return CURLE_OK, CURLE_OUT_OF_MEMORY or CURLE_URL_MALFORMAT on error.
 */
static CURLcode append2query(struct OperationConfig *config,
                             struct per_transfer *per,
                             const char *q)
{
  CURLcode result = CURLE_OK;
  if(q) {
    CURLU *uh = curl_url();
    if(uh) {
      CURLUcode uerr;
      uerr = curl_url_set(uh, CURLUPART_URL, per->url, CURLU_GUESS_SCHEME);
      if(uerr) {
        result = urlerr_cvt(uerr);
        errorf("(%d) Could not parse the URL, "
               "failed to set query", (int)result);
        config->synthetic_error = TRUE;
      }
      else {
        char *updated = NULL;
        uerr = curl_url_set(uh, CURLUPART_QUERY, q, CURLU_APPENDQUERY);
        if(!uerr)
          uerr = curl_url_get(uh, CURLUPART_URL, &updated,
                              CURLU_NO_GUESS_SCHEME);
        if(uerr)
          result = urlerr_cvt(uerr);
        else {
          /* use our new URL instead! */
          curlx_free(per->url); /* free previous URL */
          /* make it allocated by tool memory */
          per->url = curlx_strdup(updated);
          curl_free(updated);
          if(!per->url)
            result = CURLE_OUT_OF_MEMORY;
        }
      }
      curl_url_cleanup(uh);
    }
    else
      result = CURLE_OUT_OF_MEMORY;
  }
  return result;
}

/**
 * @internal
 * @brief Read the ETag from the @c --etag-compare file.
 *
 * Builds the "If-None-Match" header from the first line of the file and
 * adds it to the custom request headers.
 *
 * @param[in,out] config Operation configuration, headers are appended.
 * @return CURLE_OK (also when the file does not exist), or
 *         CURLE_OUT_OF_MEMORY.
 */
static CURLcode etag_compare(struct OperationConfig *config)
{
  CURLcode result = CURLE_OK;
  char *etag_from_file = NULL;
  char *header = NULL;
  ParameterError pe;

  /* open file for reading: */
  FILE *file = curlx_fopen(config->etag_compare_file, FOPEN_READTEXT);
  if(!file) {
    char errbuf[STRERROR_LEN];
    warnf("Failed to open %s: %s", config->etag_compare_file,
          curlx_strerror(errno, errbuf, sizeof(errbuf)));
  }

  if((PARAM_OK == file2string(&etag_from_file, file)) &&
     etag_from_file) {
    char *h = curl_maprintf("If-None-Match: %s", etag_from_file);
    curlx_safefree(etag_from_file);
    if(h) {
      /* move it to the right memory */
      header = curlx_strdup(h);
      curl_free(h);
    }
  }
  else
    header = curlx_strdup("If-None-Match: \"\"");

  if(!header) {
    if(file)
      curlx_fclose(file);
    errorf("Failed to allocate memory for custom etag header");
    return CURLE_OUT_OF_MEMORY;
  }

  /* add Etag from file to list of custom headers */
  pe = add2list(&config->headers, header);
  curlx_free(header);

  if(file)
    curlx_fclose(file);
  if(pe != PARAM_OK)
    result = CURLE_OUT_OF_MEMORY;
  return result;
}

/**
 * @internal
 * @brief Prepare the @c --etag-save output.
 *
 * Creates directories when requested and opens the file (or uses stdout).
 *
 * @param[in]     config    Operation configuration.
 * @param[in,out] etag_save Output descriptor to fill in.
 * @param[out]    skip      Set to TRUE if the transfer must be skipped.
 * @return CURLE_OK, or the error from directory creation.
 */
static CURLcode etag_store(struct OperationConfig *config,
                           struct OutStruct *etag_save,
                           bool *skip)
{
  if(config->create_dirs) {
    CURLcode result = create_dir_hierarchy(config->etag_save_file);
    if(result)
      return result;
  }

  /* open file for output: */
  if(strcmp(config->etag_save_file, "-")) {
    FILE *newfile = curlx_fopen(config->etag_save_file, "ab");
    if(!newfile) {
      warnf("Failed creating file for saving etags: \"%s\". "
            "Skip this transfer", config->etag_save_file);
      *skip = TRUE;
      return CURLE_OK;
    }
    else {
      etag_save->filename = config->etag_save_file;
      etag_save->regular_file = TRUE;
      etag_save->fopened = TRUE;
      etag_save->stream = newfile;
    }
  }
  else {
    /* always use binary mode for protocol header output */
    CURL_BINMODE(etag_save->stream);
  }
  return CURLE_OK;
}

/**
 * @internal
 * @brief Open the @c --dump-header file.
 *
 * Handles "-" (stdout), "%" (stderr) and regular files, which are opened
 * in binary mode.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] per    Transfer owning the header output.
 * @param[in,out] heads  Header output descriptor to fill in.
 * @return CURLE_OK, or CURLE_WRITE_ERROR if the file cannot be opened.
 */
static CURLcode setup_headerfile(struct OperationConfig *config,
                                 struct per_transfer *per,
                                 struct OutStruct *heads)
{
  if(config->headerfile) {
    /* open file for output: */
    if(!strcmp(config->headerfile, "%")) {
      heads->stream = stderr;
      /* use binary mode for protocol header output */
      CURL_BINMODE(heads->stream);
    }
    else if(strcmp(config->headerfile, "-")) {
      FILE *newfile;

      /*
       * Since every transfer has its own file handle for dumping
       * the headers, we need to open it in append mode, since transfers
       * might finish in any order.
       * The first transfer clears the file.
       *
       * Consider placing the file handle inside the OperationConfig, so
       * that it does not need to be opened/closed for every transfer.
       */
      if(config->create_dirs) {
        CURLcode result = create_dir_hierarchy(config->headerfile);
        /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
        if(result)
          return result;
      }
      if(!per->prev || per->prev->config != config) {
        newfile = curlx_fopen(config->headerfile, "wb");
        if(newfile)
          curlx_fclose(newfile);
      }
      newfile = curlx_fopen(config->headerfile, "ab");

      if(!newfile) {
        errorf("Failed to open %s", config->headerfile);
        return CURLE_WRITE_ERROR;
      }
      else {
        heads->filename = config->headerfile;
        heads->regular_file = TRUE;
        heads->fopened = TRUE;
        heads->stream = newfile;
      }
    }
    else {
      /* always use binary mode for protocol header output */
      CURL_BINMODE(heads->stream);
    }
  }
  return CURLE_OK;
}

/**
 * @internal
 * @brief Figure out and populate the output file name (per->outfile).
 *
 * Derives the name from @c -o / @c -O, creates directories, avoids
 * clobbering existing files when asked and handles resume.
 *
 * @param[in]     config  Operation configuration.
 * @param[in,out] per     Transfer to configure.
 * @param[in]     u       URL node holding the output options.
 * @param[in,out] outs    Output descriptor to fill in.
 * @param[out]    skipped Set to TRUE if this transfer must be skipped.
 * @return CURLE_OK, CURLE_WRITE_ERROR, CURLE_OUT_OF_MEMORY or the error
 *         from directory creation.
 */
static CURLcode setup_outfile(struct OperationConfig *config,
                              struct per_transfer *per,
                              struct getout *u,
                              struct OutStruct *outs,
                              bool *skipped)
{
  struct State *state = &global->state;

  outs->out_null = u->out_null;
  /* if --out-null or output to stdout, return */
  if(outs->out_null ||
     (!u->useremote && (!u->outfile || !strcmp("-", u->outfile)))) {
    per->outfile = u->outfile;
    u->outfile = NULL;
    return CURLE_OK;
  }

  if(!u->outfile) {
    SANITIZEcode sc;
    /* extract the filename from the URL */
    CURLcode result = get_url_file_name(&per->outfile, per->url, &sc);
    if(sc) {
      if(sc == SANITIZE_ERR_OUT_OF_MEMORY)
        return CURLE_OUT_OF_MEMORY;
      if(sc == SANITIZE_ERR_INVALID_PATH)
        errorf("bad output filename");
      return result;
    }
    else if(result) {
      errorf("Failed to extract a filename from the URL to use for storage");
      return result;
    }
  }
  else if(glob_inuse(&state->urlglob) || glob_inuse(&state->inglob)) {
    /* expand '#1' ... '#9' references from URL pattern and named references
       from the upload file glob */
    SANITIZEcode sc;
    CURLcode result =
      glob_match_url(&per->outfile, u->outfile, &state->urlglob,
                     glob_inuse(&state->inglob) ? &state->inglob : NULL, &sc);

    if(sc) {
      if(sc == SANITIZE_ERR_OUT_OF_MEMORY)
        return CURLE_OUT_OF_MEMORY;
      if(sc == SANITIZE_ERR_INVALID_PATH)
        warnf("bad output filename");
      return result;
    }
    else if(result) {
      /* bad globbing */
      if(state->urlglob.error) {
        glob_show_error(&state->urlglob, u->outfile, tool_stderr, result);
        config->synthetic_error = TRUE;
      }
      else
        warnf("bad output glob");
      return result;
    }
    if(!*per->outfile) {
      warnf("output glob produces empty string");
      return CURLE_WRITE_ERROR;
    }
  }
  else {
    per->outfile = curlx_strdup(u->outfile);
    if(!per->outfile)
      return CURLE_OUT_OF_MEMORY;
  }

  DEBUGASSERT(per->outfile);

  if(config->output_dir && *config->output_dir) {
    char *d = curl_maprintf("%s/%s", config->output_dir, per->outfile);
    curlx_safefree(per->outfile);
    if(d) {
      per->outfile = curlx_strdup(d); /* move to right memory */
      curl_free(d);
    }
    if(!d || !per->outfile)
      return CURLE_WRITE_ERROR;
  }
  /* Create the directory hierarchy, if not pre-existent to a multiple
     file output call */

  if(config->create_dirs) {
    CURLcode result = create_dir_hierarchy(per->outfile);
    /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
    if(result)
      return result;
  }

  if(config->skip_existing) {
    curlx_struct_stat fileinfo;
    if(!curlx_stat(per->outfile, &fileinfo)) {
      /* file is present */
      notef("skips transfer, \"%s\" exists locally", per->outfile);
      per->skip = TRUE;
      *skipped = TRUE;
    }
  }

  if(config->resume_from_current) {
    /* We are told to continue from where we are now. Get the size
       of the file as it is now and open it for append instead */
    curlx_struct_stat fileinfo;
    /* VMS -- Danger, the filesize is only valid for stream files */
    if(curlx_stat(per->outfile, &fileinfo) == 0)
      /* set offset to current file size: */
      config->resume_from = fileinfo.st_size;
    else
      /* let offset be 0 */
      config->resume_from = 0;
  }

  if(config->resume_from) {
#ifdef __VMS
    /* open file for output, forcing VMS output format into stream
       mode which is needed for stat() call above to always work. */
    FILE *file = curlx_fopen(per->outfile, "ab",
                             "ctx=stm", "rfm=stmlf", "rat=cr", "mrs=0");
#else
    /* open file for output: */
    FILE *file = curlx_fopen(per->outfile, "ab");
#endif
    if(!file) {
      errorf("cannot open '%s'", per->outfile);
      return CURLE_WRITE_ERROR;
    }
    outs->fopened = TRUE;
    outs->stream = file;
    outs->init = config->resume_from;
  }
  else {
    outs->stream = NULL; /* open when needed */
  }
  outs->filename = per->outfile;
  outs->regular_file = TRUE;
  return CURLE_OK;
}

/**
 * @internal
 * @brief Prepare uploading from stdin.
 *
 * Warns about multiple auth methods (needs a rewindable body), switches
 * stdin to non-blocking if requested and sets the input file descriptor.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] per    Transfer being set up.
 */
static void check_stdin_upload(struct OperationConfig *config,
                               struct per_transfer *per)
{
  /* count to see if there are more than one auth bit set
     in the authtype field */
  int authbits = 0;
  int bitcheck = 0;
  while(bitcheck < 32) {
    if(config->authtype & (1UL << bitcheck++)) {
      authbits++;
      if(authbits > 1) {
        /* more than one, we are done! */
        break;
      }
    }
  }

  /*
   * If the user has also selected --anyauth or --proxy-anyauth
   * we should warn them.
   */
  if(config->proxyanyauth || (authbits > 1)) {
    warnf("Using --anyauth or --proxy-anyauth with upload from stdin"
          " involves a big risk of it not working. Use a temporary"
          " file or a fixed auth type instead");
  }

  DEBUGASSERT(per->infdopen == FALSE);
  DEBUGASSERT(per->infd == STDIN_FILENO);

  CURL_BINMODE(stdin);
  if(!strcmp(per->uploadfile, ".")) {
#if defined(USE_WINSOCK) && !defined(CURL_WINDOWS_UWP)
    /* non-blocking stdin behavior on Windows is challenging
       Spawn a new thread that reads from stdin and write
       out to a socket */
    curl_socket_t f = win32_stdin_read_thread();

    if(f == CURL_SOCKET_BAD)
      warnf("win32_stdin_read_thread returned INVALID_SOCKET "
            "falling back to blocking mode");
    else if(f > INT_MAX) {
      warnf("win32_stdin_read_thread returned identifier "
            "larger than INT_MAX. This should not happen unless "
            "the upper 32 bits of a Windows socket have started "
            "being used for something... falling back to blocking "
            "mode");
      sclose(f);
    }
    else
      per->infd = (int)f;
#endif
    if(curlx_nonblock((curl_socket_t)per->infd, TRUE) < 0) {
      char errbuf[STRERROR_LEN];
      warnf("fcntl failed on fd=%d: %s", per->infd,
            curlx_strerror(errno, errbuf, sizeof(errbuf)));
    }
  }
}

/**
 * @internal
 * @brief Fill in the data struct passed to the header callback.
 *
 * @param[in]  config    Operation configuration.
 * @param[out] hdrcbdata Callback data to populate.
 * @param[in]  u         URL node (decides Content-Disposition naming).
 * @param[in]  outs      Body output descriptor.
 * @param[in]  heads     Header output descriptor.
 * @param[in]  etag      ETag output descriptor.
 * @warning The pointers are stored, not copied: they must outlive the
 *          transfer.
 */
static void setup_header_cb(struct OperationConfig *config,
                            struct HdrCbData *hdrcbdata,
                            struct getout *u,
                            struct OutStruct *outs,
                            struct OutStruct *heads,
                            struct OutStruct *etag)
{
  hdrcbdata->honor_cd_filename = (config->content_disposition && u->useremote);
  hdrcbdata->outs = outs;
  hdrcbdata->heads = heads;
  hdrcbdata->etag_save = etag;
  hdrcbdata->config = config;
}

/**
 * @internal
 * @brief Resolve the upload file name from a --upload-file glob.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] state  Global iteration state (glob and upload name).
 * @param[in]     u      URL node with the upload file specification.
 * @param[in]     err    Stream for glob error messages.
 * @return CURLE_OK, or a glob/memory error code.
 */
static CURLcode setup_input_file(struct OperationConfig *config,
                                 struct State *state, struct getout *u,
                                 FILE *err)
{
  CURLcode result = CURLE_OK;
  if(u->infile) {
    if(!config->globoff && !glob_inuse(&state->inglob))
      result = glob_url(&state->inglob, u->infile, &state->upnum, err);
    if(!result && !state->uploadfile) {
      if(glob_inuse(&state->inglob) &&
         !glob_is_literal(&state->inglob))
        result = glob_next_url(&state->uploadfile, &state->inglob);
      else if(!state->upidx) {
        /* take ownership of the allocated string */
        state->uploadfile = u->infile;
        u->infile = NULL;
      }
    }
  }
  return result;
}

/**
 * @internal
 * @brief Expand the URL pattern into a list of URLs.
 *
 * Unless globbing is turned off, '{...}' and '[...]' expressions are
 * expanded and the total URL count is stored in state->urlnum.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] state  Global iteration state.
 * @param[in]     u      URL node with the pattern.
 * @param[in]     err    Stream for glob error messages.
 * @return CURLE_OK, or the error from glob_url().
 */
static CURLcode setup_url_pattern(struct OperationConfig *config,
                                  struct State *state, struct getout *u,
                                  FILE *err)
{
  CURLcode result = CURLE_OK;
  if(!state->urlnum) {
    if(!config->globoff && !u->noglob) {
      /* Unless explicitly shut off, we expand '{...}' and '[...]'
         expressions and return total number of URLs in pattern set */
      result = glob_url(&state->urlglob, u->url, &state->urlnum, err);
    }
    else
      state->urlnum = 1; /* without globbing, this is a single URL */
  }
  return result;
}

/**
 * @internal
 * @brief Set up the @c --etag-save and @c --etag-compare handling.
 *
 * @param[in]  config     Operation configuration.
 * @param[out] etag_save  ETag output descriptor, zeroed and initialised.
 * @param[out] break_loop Set to TRUE if no transfer should be made.
 * @return CURLE_OK or the error from etag_store() / etag_compare().
 */
static CURLcode setup_etag_files(struct OperationConfig *config,
                                 struct OutStruct *etag_save,
                                 bool *break_loop)
{
  CURLcode result = CURLE_OK;
  *break_loop = FALSE;

  /* --etag-save */
  memset(etag_save, 0, sizeof(*etag_save));
  etag_save->stream = stdout;

  /* --etag-compare */
  if(config->etag_compare_file) {
    result = etag_compare(config);
    if(result)
      return result;
  }

  if(config->etag_save_file) {
    bool badetag = FALSE;
    result = etag_store(config, etag_save, &badetag);
    if(result || badetag) {
      *break_loop = TRUE;
      return result;
    }
  }
  return result;
}

/**
 * @internal
 * @brief Select the URL for the next transfer.
 *
 * Takes the next glob result, or the literal URL for the first iteration.
 *
 * @param[in,out] state Global iteration state.
 * @param[in]     u     URL node.
 * @param[out]    url   Newly allocated URL, or NULL when none is left.
 * @return CURLE_OK or CURLE_OUT_OF_MEMORY.
 * @note The caller owns the returned string.
 */
static CURLcode select_next_url(struct State *state,
                                struct getout *u,
                                char **url)
{
  CURLcode result = CURLE_OK;
  if(glob_inuse(&state->urlglob) &&
     !glob_is_literal(&state->urlglob))
    result = glob_next_url(url, &state->urlglob);
  else if(!state->urlidx) {
    *url = curlx_strdup(u->url);
    if(!*url)
      result = CURLE_OUT_OF_MEMORY;
  }
  else
    *url = NULL;
  return result;
}

/**
 * @internal
 * @brief Configure the upload part of a transfer.
 *
 * Handles stdin uploads and appends the file name to URLs that end with a
 * slash.
 *
 * @param[in]     config Operation configuration.
 * @param[in,out] per    Transfer being set up.
 * @return CURLE_OK or the error from add_file_name_to_url().
 */
static CURLcode setup_transfer_upload(struct OperationConfig *config,
                                      struct per_transfer *per)
{
  CURLcode result = CURLE_OK;
  if(per->uploadfile) {
    if(stdin_upload(per->uploadfile))
      check_stdin_upload(config, per);
    else {
      /* We have specified a file to upload and it is not "-" */
      result = add_file_name_to_url(per->curl, &per->url, per->uploadfile);
      if(result)
        return result;
    }

    if(config->resume_from_current)
      config->resume_from = -1; /* -1 then forces get-it-yourself */
  }
  return result;
}

/**
 * @internal
 * @brief Tell whether the given stream is a terminal.
 *
 * @param[in] stream Stream to test.
 * @return TRUE for a terminal, FALSE otherwise.
 * @note Debug builds honour the CURL_ISATTY environment variable, which the
 *       test suite uses to simulate a terminal.
 */
static bool stream_isatty(FILE *stream)
{
#ifdef DEBUGBUILD
  /* the test suite sets CURL_ISATTY to make curl act as if the output goes
     to a terminal */
  if(getenv("CURL_ISATTY"))
    return TRUE;
#endif
  return !!isatty(fileno(stream));
}

/**
 * @internal
 * @brief Create a single transfer for the next URL.
 *
 * Allocates a per_transfer, configures output, headers, upload and every
 * easy option from the config, and registers it for execution.
 *
 * @param[in,out] config  Operation configuration.
 * @param[in]     share   Share object attached to the easy handle.
 * @param[in,out] state   Global iteration state.
 * @param[out]    added   Set to TRUE if a transfer was created.
 * @param[out]    skipped Set to TRUE if the URL was skipped.
 * @return CURLE_OK on success, or the error that prevented creation
 *         (for example CURLE_OUT_OF_MEMORY or CURLE_FAILED_INIT).
 * @post On success *added is TRUE and the node is in the transfers list.
 */
static CURLcode create_single(struct OperationConfig *config,
                              CURLSH *share, struct State *state,
                              bool *added, bool *skipped)
{
  const bool orig_isatty = (bool)global->isatty;
  const bool orig_noprogress = (bool)global->noprogress;
  CURLcode result = CURLE_OK;
  while(state->urlnode) {
    struct per_transfer *per = NULL;
    struct OutStruct *outs;
    struct OutStruct *heads;
    struct OutStruct etag_first;
    CURL *curl;
    struct getout *u = state->urlnode;
    FILE *err = (!global->silent || global->showerror) ? tool_stderr : NULL;
    bool break_loop = FALSE;

    if(!u->url) {
      /* This node has no URL. End of the road. */
      warnf("Got more output options than URLs");
      break;
    }

    result = setup_input_file(config, state, u, err);
    if(result)
      return result;

    if(state->upidx >= state->upnum) {
      state->urlnum = 0;
      curlx_safefree(state->uploadfile);
      glob_cleanup(&state->inglob);
      state->upidx = 0;
      state->urlnode = u->next; /* next node */
      state->upnum = 1;
      continue;
    }

    result = setup_url_pattern(config, state, u, err);
    if(result)
      return result;

    result = setup_etag_files(config, &etag_first, &break_loop);
    if(result || break_loop)
      return result;

    curl = curl_easy_init();
    if(curl)
      result = add_per_transfer(&per);
    else
      result = CURLE_OUT_OF_MEMORY;
    if(result) {
      curl_easy_cleanup(curl);
      if(etag_first.fopened)
        curlx_fclose(etag_first.stream);
      return result;
    }
    per->etag_save = etag_first; /* copy the whole struct */
    if(state->uploadfile) {
      per->uploadfile = curlx_strdup(state->uploadfile);
      if(!per->uploadfile ||
         SetHTTPrequest(TOOL_HTTPREQ_PUT, &config->httpreq)) {
        curlx_safefree(per->uploadfile);
        curl_easy_cleanup(curl);
        return CURLE_FAILED_INIT;
      }
    }
    per->config = config;
    per->curl = curl;
    per->urlnum = u->num;
    per->out_scheme = NULL;

    /* default headers output stream is stdout */
    heads = &per->heads;
    heads->stream = stdout;

    /* Single header file for all URLs */
    result = setup_headerfile(config, per, heads);
    if(result)
      return result;
    outs = &per->outs;

    per->infdopen = FALSE;
    per->infd = STDIN_FILENO;

    /* default output stream is stdout */
    outs->stream = stdout;

    result = select_next_url(state, u, &per->url);
    if(result)
      return result;
    if(!per->url)
      break;

    result = setup_outfile(config, per, u, outs, skipped);
    if(result)
      return result;

    result = setup_transfer_upload(config, per);
    if(result)
      return result;

    if(!outs->out_null && output_expected(per->url, per->uploadfile) &&
       outs->stream && stream_isatty(outs->stream))
      /* we send the output to a tty, therefore we switch off the progress
         meter */
      per->noprogress = global->noprogress = global->isatty = TRUE;
    else {
      /* progress meter is per download, so restore config values */
      per->noprogress = global->noprogress = orig_noprogress;
      global->isatty = orig_isatty;
    }

    result = append2query(config, per, config->httpgetfields);
    if(result)
      return result;

    if((!per->outfile || !strcmp(per->outfile, "-")) &&
       !config->use_ascii) {
      /* We get the output to stdout and we have not got the ASCII/text flag,
         then set stdout to be binary */
      CURL_BINMODE(stdout);
    }

    /* explicitly passed to stdout means okaying binary gunk */
    config->terminal_binary_ok = (per->outfile && !strcmp(per->outfile, "-"));

    setup_header_cb(config, &per->hdrcbdata, u, outs, heads, &etag_first);

    result = config2setopts(config, per, curl, share);
    if(result)
      return result;

    /* initialize retry vars for loop below */
    per->retry_sleep_default = config->retry_delay_ms;
    per->retry_remaining = config->req_retry;
    per->retry_sleep = per->retry_sleep_default; /* ms */
    per->retrystart = curlx_now();

    /* Here's looping around each globbed URL */
    if(++state->urlidx >= state->urlnum) {
      state->urlidx = state->urlnum = 0;
      glob_cleanup(&state->urlglob);
      state->upidx++;
      curlx_safefree(state->uploadfile); /* clear it to get the next */
    }
    *added = TRUE;
    break;
  }
  return result;
}

/**
 * @internal
 * @brief Create the next (singular) transfer.
 *
 * Prepares the URL and upload glob state, folds @c --get fields into the
 * query and calls create_single().
 *
 * @param[in,out] config  Operation configuration.
 * @param[in]     share   Share object for the new handle.
 * @param[out]    added   Set to TRUE if a transfer was added.
 * @param[out]    skipped Set to TRUE if the URL was skipped.
 * @return CURLE_OK or an error from setup.
 * @see create_single()
 */
static CURLcode single_transfer(struct OperationConfig *config,
                                CURLSH *share, bool *added, bool *skipped)
{
  CURLcode result = CURLE_OK;
  struct State *state = &global->state;
  char *httpgetfields = config->httpgetfields;

  *skipped = *added = FALSE; /* not yet */

  if(config->postfields) {
    if(config->use_httpget) {
      if(!httpgetfields) {
        /* Use the postfields data for an HTTP get */
        httpgetfields = config->httpgetfields = config->postfields;
        config->postfields = NULL;
        if(SetHTTPrequest((config->no_body ? TOOL_HTTPREQ_HEAD :
                           TOOL_HTTPREQ_GET), &config->httpreq))
          return CURLE_FAILED_INIT;
      }
    }
    else if(SetHTTPrequest(TOOL_HTTPREQ_SIMPLEPOST, &config->httpreq))
      return CURLE_FAILED_INIT;
  }
  if(!httpgetfields)
    config->httpgetfields = config->query;

  result = set_cert_types(config);
  if(result)
    return result;

  if(!state->urlnode) {
    /* first time caller, setup things */
    state->urlnode = config->url_list;
    state->upnum = 1;
  }

  return create_single(config, share, state, added, skipped);
}

/**
 * @internal
 * @brief Number of easy handles currently added to the multi handle.
 */
static long all_added; /* number of easy handles currently added */

/**
 * @internal
 * @brief Add transfers to the multi handle up to the parallel limit.
 *
 * Creates new transfers when needed and adds them to the multi handle,
 * honouring @c --parallel-max and per-transfer start delays (retries).
 *
 * @param[in]  multi  Multi handle.
 * @param[in]  share  Share object for new transfers.
 * @param[out] morep  TRUE if more transfers may still be added later.
 * @param[out] addedp TRUE if one or more transfers were added.
 * @return CURLE_OK, or the error that stopped creating transfers.
 */
static CURLcode add_parallel_transfers(CURLM *multi, CURLSH *share,
                                       bool *morep, bool *addedp)
{
  struct per_transfer *per;
  CURLcode result = CURLE_OK;
  CURLMcode mcode;
  bool sleeping = FALSE;
  curl_off_t nxfers;

  *addedp = FALSE;
  *morep = FALSE;
  mcode = curl_multi_get_offt(multi, CURLMINFO_XFERS_CURRENT, &nxfers);
  if(mcode) {
    DEBUGASSERT(0);
    return CURLE_UNKNOWN_OPTION;
  }

  if(all_added >= global->parallel_max) {
    /* we are at max parallelism, no need to create more transfers */
    *morep = TRUE; /* pretend there are, we have not checked */
    return CURLE_OK;
  }
  /* if the list is empty, create one to kickstart the loop */
  if(!transfers) {
    bool skipped = FALSE;
    do {
      result = create_transfer(share, addedp, &skipped);
      if(result)
        return result;
    } while(skipped);
  }
  /* add transfers until max parallelism is achieved again */
  for(per = transfers; per && (all_added < global->parallel_max);
      per = per->next) {
    if(per->added || per->skip)
      /* already added or to be skipped */
      continue;
    if(per->startat && (time(NULL) < per->startat)) {
      /* this is still delaying */
      sleeping = TRUE;
      continue;
    }
    per->added = TRUE;

    result = pre_transfer(per);
    if(result)
      return result;

    /* parallel connect means that we do not set PIPEWAIT since pipewait
       makes libcurl prefer multiplexing */
    (void)curl_easy_setopt(per->curl, CURLOPT_PIPEWAIT,
                           global->parallel_connect ? 0L : 1L);
    (void)curl_easy_setopt(per->curl, CURLOPT_PRIVATE, per);
    /* curl does not use signals, switching this on saves some system calls */
    (void)curl_easy_setopt(per->curl, CURLOPT_NOSIGNAL, 1L);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
    (void)curl_easy_setopt(per->curl, CURLOPT_XFERINFODATA, per);
    (void)curl_easy_setopt(per->curl, CURLOPT_NOPROGRESS, 0L);
    (void)curl_easy_setopt(per->curl, CURLOPT_ERRORBUFFER, per->errorbuffer);
#ifdef DEBUGBUILD
    if(getenv("CURL_FORBID_REUSE"))
      (void)curl_easy_setopt(per->curl, CURLOPT_FORBID_REUSE, 1L);
#endif

    mcode = curl_multi_add_handle(multi, per->curl);
    if(mcode) {
      DEBUGASSERT(mcode == CURLM_OUT_OF_MEMORY);
      result = CURLE_OUT_OF_MEMORY;
    }

    if(!result) {
      bool getadded = FALSE;
      bool skipped = FALSE;
      do {
        result = create_transfer(share, &getadded, &skipped);
        if(result)
          break;
      } while(skipped);
    }
    if(result)
      return result;

    per->errorbuffer[0] = 0;
    per->added = TRUE;
    all_added++;
    *addedp = TRUE;
  }
  *morep = (per || sleeping);
  return CURLE_OK;
}

/**
 * @internal
 * @brief State of a parallel run (shared with the callbacks).
 */
struct parastate {
  CURLM *multi; ///< multi handle
  CURLSH *share; ///< share object
  CURLMcode mcode; ///< last multi code
  CURLcode result; ///< first transfer error
  int still_running; ///< running transfers
  struct curltime start; ///< start time
  bool more_transfers; ///< more may be added
  bool added_transfers; ///< any added this round
  /* wrapitup is set TRUE after a critical error occurs to end all transfers */
  bool wrapitup;
  /* wrapitup_processed is set TRUE after the per transfer abort flag is set */
  bool wrapitup_processed;
  time_t tick; ///< last progress tick
};

#if defined(DEBUGBUILD) && defined(USE_LIBUV)

/**
 * @internal
 * @brief Debug switch for libuv event tracing (0 = off).
 */
#define DEBUG_UV 0

/**
 * @internal
 * @brief Object passed to the libuv/libcurl callbacks.
 */
struct datauv {
  uv_timer_t timeout; ///< timeout timer
  uv_loop_t *loop; ///< event loop
  struct parastate *s; ///< parent state
};

/**
 * @internal
 * @brief Per-socket context for libuv polling.
 */
struct contextuv {
  uv_poll_t poll_handle; ///< poll handle
  curl_socket_t sockfd; ///< watched socket
  struct datauv *uv; ///< owner
};

/**
 * @brief Forward declaration of the multi notification callback.
 * @see mnotify()
 */
static void mnotify(CURLM *multi, unsigned int notification,
                    CURL *easy, void *user_data);

/**
 * @internal
 * @brief libuv callback on socket activity.
 *
 * Translates libuv events into CURL_CSELECT_* flags and informs libcurl.
 *
 * @param[in] req    Poll handle; its data points to a contextuv.
 * @param[in] status libuv status (unused).
 * @param[in] events UV_READABLE and/or UV_WRITABLE bits.
 */
static void on_uv_socket(uv_poll_t *req, int status, int events)
{
  int flags = 0;
  struct contextuv *c = (struct contextuv *)req->data;
  (void)status;
  if(events & UV_READABLE)
    flags |= CURL_CSELECT_IN;
  if(events & UV_WRITABLE)
    flags |= CURL_CSELECT_OUT;

  curl_multi_socket_action(c->uv->s->multi, c->sockfd, flags,
                           &c->uv->s->still_running);
  progress_meter(c->uv->s->multi, &c->uv->s->start, FALSE);
}

/**
 * @internal
 * @brief libuv callback when the timeout expires.
 *
 * @param[in] req Timer handle; its data points to a datauv.
 */
static void on_uv_timeout(uv_timer_t *req)
{
  struct datauv *uv = (struct datauv *)req->data;
#if DEBUG_UV
  curl_mfprintf(tool_stderr, "parallel_event: on_uv_timeout\n");
#endif
  if(uv && uv->s) {
    curl_multi_socket_action(uv->s->multi, CURL_SOCKET_TIMEOUT, 0,
                             &uv->s->still_running);
    progress_meter(uv->s->multi, &uv->s->start, FALSE);
  }
}

/**
 * @internal
 * @brief libcurl callback to update the timeout expiry.
 *
 * @param[in] multi      Multi handle (unused).
 * @param[in] timeout_ms New timeout, -1 deletes the timer, 0 means asap.
 * @param[in] userp      The datauv object.
 * @return Always 0.
 */
static int cb_timeout(CURLM *multi, long timeout_ms, void *userp)
{
  struct datauv *uv = userp;
  (void)multi;
#if DEBUG_UV
  curl_mfprintf(tool_stderr, "parallel_event: cb_timeout=%ld\n", timeout_ms);
#endif
  if(timeout_ms < 0)
    uv_timer_stop(&uv->timeout);
  else {
    if(timeout_ms == 0)
      timeout_ms = 1; /* 0 means call curl_multi_socket_action asap but NOT
                         within the callback itself */
    uv_timer_start(&uv->timeout, on_uv_timeout, timeout_ms,
                   0); /* do not repeat */
  }
  return 0;
}

/**
 * @internal
 * @brief Allocate a socket context and init its poll handle.
 *
 * @param[in] sockfd Socket to watch.
 * @param[in] uv     Owning datauv.
 * @return New context; released by close_cb() after destroy_context().
 */
static struct contextuv *create_context(curl_socket_t sockfd,
                                        struct datauv *uv)
{
  struct contextuv *c = curlx_malloc(sizeof(*c));

  c->sockfd = sockfd;
  c->uv = uv;

  uv_poll_init_socket(uv->loop, &c->poll_handle, sockfd);
  c->poll_handle.data = c;

  return c;
}

/**
 * @internal
 * @brief libuv close callback; frees the socket context.
 *
 * @param[in] handle Closed poll handle, its data is the contextuv.
 */
static void close_cb(uv_handle_t *handle)
{
  struct contextuv *c = (struct contextuv *)handle->data;
  curlx_free(c);
}

/**
 * @internal
 * @brief Start closing the poll handle of a socket context.
 *
 * @param[in] c Context to destroy.
 * @warning The memory is freed asynchronously by close_cb().
 */
static void destroy_context(struct contextuv *c)
{
  uv_close((uv_handle_t *)&c->poll_handle, close_cb);
}

/**
 * @internal
 * @brief libcurl callback to update the socket activity to wait for.
 *
 * @param[in] easy    Easy handle (unused).
 * @param[in] s       Socket.
 * @param[in] action  CURL_POLL_IN, _OUT, _INOUT or _REMOVE.
 * @param[in] userp   The datauv object.
 * @param[in] socketp Per-socket context set earlier, or NULL.
 * @return 0 on success, -1 on an unknown action.
 */
static int cb_socket(CURL *easy, curl_socket_t s, int action,
                     void *userp, void *socketp)
{
  struct contextuv *c;
  int events = 0;
  struct datauv *uv = userp;
  (void)easy;

#if DEBUG_UV
  curl_mfprintf(tool_stderr, "parallel_event: cb_socket, "
                "fd=%" FMT_SOCKET_T ", action=%x, p=%p\n", s, action, socketp);
#endif
  switch(action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    c = socketp ? (struct contextuv *)socketp : create_context(s, uv);

    curl_multi_assign(uv->s->multi, s, c);

    if(action != CURL_POLL_IN)
      events |= UV_WRITABLE;
    if(action != CURL_POLL_OUT)
      events |= UV_READABLE;

    uv_poll_start(&c->poll_handle, events, on_uv_socket);
    break;
  case CURL_POLL_REMOVE:
    if(socketp) {
      c = (struct contextuv *)socketp;
      uv_poll_stop(&c->poll_handle);
      destroy_context(c);
      curl_multi_assign(uv->s->multi, s, NULL);
    }
    break;
  default:
    DEBUGASSERT(0);
    return -1;
  }

  return 0;
}

/**
 * @internal
 * @brief Run the parallel transfers using libuv (debug builds only).
 *
 * @param[in,out] s Parallel state.
 * @return CURLE_OK, or the first failing transfer result.
 */
static CURLcode parallel_event(struct parastate *s)
{
  CURLcode result = CURLE_OK;
  struct datauv uv = { 0 };

  s->result = CURLE_OK;
  uv.s = s;
  uv.loop = uv_default_loop();
  uv_timer_init(uv.loop, &uv.timeout);
  uv.timeout.data = &uv;

  /* setup event callbacks */
  curl_multi_setopt(s->multi, CURLMOPT_SOCKETFUNCTION, cb_socket);
  curl_multi_setopt(s->multi, CURLMOPT_SOCKETDATA, &uv);
  curl_multi_setopt(s->multi, CURLMOPT_TIMERFUNCTION, cb_timeout);
  curl_multi_setopt(s->multi, CURLMOPT_TIMERDATA, &uv);
  curl_multi_setopt(s->multi, CURLMOPT_MAX_HOST_CONNECTIONS, (long)
                    global->parallel_host);

  /* kickstart the thing */
  curl_multi_socket_action(s->multi, CURL_SOCKET_TIMEOUT, 0,
                           &s->still_running);

  while(!s->mcode && (s->still_running || s->more_transfers)) {

    if(!s->still_running && s->more_transfers) {
      curl_off_t nxfers;
      /* None are running, but there may be more ready to run. Try
       * to add more when possible. */
      s->result = add_parallel_transfers(s->multi, s->share,
                                         &s->more_transfers,
                                         &s->added_transfers);
      if(s->result)
        break;
      if(s->more_transfers) {
        /* There are still more transfers, so not all were added. If we
         * did not add *any*, it means there is nothing to do until time
         * passes and a transfer becomes ready to add.
         * Avoid busy looping by taking a small break. */
        CURLMcode mcode = curl_multi_get_offt(
          s->multi, CURLMINFO_XFERS_CURRENT, &nxfers);
        if(!mcode && !nxfers) {
          /* None have been added, must be waiting on a timeout */
          curlx_wait_ms(500);
        }
      }
    }
#if DEBUG_UV
    curl_mfprintf(tool_stderr, "parallel_event: uv_run(), "
                  "mcode=%d, %d running, %d more\n",
                  s->mcode, uv.s->still_running, s->more_transfers);
#endif
    uv_run(uv.loop, UV_RUN_DEFAULT);
#if DEBUG_UV
    curl_mfprintf(tool_stderr, "parallel_event: uv_run() returned\n");
#endif

    /* early exit called */
    if(s->wrapitup) {
      if(s->still_running && !s->wrapitup_processed) {
        struct per_transfer *per;
        for(per = transfers; per; per = per->next) {
          if(per->added)
            per->abort = TRUE;
        }
        s->wrapitup_processed = TRUE;
      }
      break;
    }
  }

  result = s->result;

  /* Make sure to return some kind of error if there was a multi problem */
  if(s->mcode) {
    result = (s->mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  /* We need to cleanup the multi here, since the uv context lives on the
   * stack and about to be gone. multi_cleanup can trigger events! */
  (void)progress_meter(s->multi, &s->start, TRUE);
  curl_multi_cleanup(s->multi);

#if DEBUG_UV
  curl_mfprintf(tool_stderr, "DONE parallel_event -> %d, mcode=%d, "
          "%d running, %d more\n",
          result, s->mcode, uv.s->still_running, s->more_transfers);
#endif
  return result;
}

#endif

/**
 * @internal
 * @brief Handle finished transfers reported by the multi handle.
 *
 * Reads messages with curl_multi_info_read(), runs post_per_transfer(),
 * schedules retries and removes completed handles.
 *
 * @param[in,out] s Parallel state.
 * @return CURLE_OK, or the first failure; sets s->wrapitup on fatal
 *         errors or when --fail-early is active.
 * @see post_per_transfer()
 */
static CURLcode check_finished(struct parastate *s)
{
  CURLcode result = CURLE_OK;
  int rc;
  CURLMsg *msg;
  bool checkmore = FALSE;
  do {
    msg = curl_multi_info_read(s->multi, &rc);
    if(msg) {
      bool retry;
      uint32_t delay;
      struct per_transfer *ended;
      CURL *easy = msg->easy_handle;
      CURLcode tres = msg->data.result;
      curl_easy_getinfo(easy, CURLINFO_PRIVATE, &ended);
      curl_multi_remove_handle(s->multi, easy);

      if(ended->abort && (tres == CURLE_ABORTED_BY_CALLBACK)) {
        curl_msnprintf(ended->errorbuffer, CURL_ERROR_SIZE,
                       "Transfer aborted due to critical error "
                       "in another transfer");
      }
      tres = post_per_transfer(ended, tres, &retry, &delay);
      all_added--; /* one fewer added */
      checkmore = TRUE;
      if(retry) {
        progress_reset_retry(ended);
        ended->added = FALSE; /* add it again */
        /* we delay retries in full integer seconds only */
        ended->startat = delay ? time(NULL) + (delay / 1000) : 0;
      }
      else {
        progress_finalize(ended); /* before it goes away */
        /* result receives this transfer's error unless the transfer was
           marked for abort due to a critical error in another transfer */
        if(tres && (!ended->abort || !result))
          result = tres;
        if(is_fatal_error(result) || (result && global->fail_early))
          s->wrapitup = TRUE;
        (void)del_per_transfer(ended);
      }
    }
  } while(msg);
  if(!s->wrapitup) {
    if(!checkmore) {
      time_t tock = time(NULL);
      if(s->tick != tock) {
        checkmore = TRUE;
        s->tick = tock;
      }
    }
    if(checkmore) {
      /* one or more transfers completed, add more! */
      CURLcode tres = add_parallel_transfers(s->multi, s->share,
                                             &s->more_transfers,
                                             &s->added_transfers);
      if(tres)
        result = tres;
      if(s->added_transfers)
        /* we added new ones, make sure the loop does not exit yet */
        s->still_running = 1;
    }
    if(is_fatal_error(result) || (result && global->fail_early))
      s->wrapitup = TRUE;
  }
  return result;
}

/**
 * @internal
 * @brief Multi notification callback.
 *
 * On CURLMNOTIFY_INFO_READ it calls check_finished(), remembering the
 * first failure in the parallel state.
 *
 * @param[in] multi        Multi handle (unused).
 * @param[in] notification Kind of notification.
 * @param[in] easy         Easy handle (unused).
 * @param[in] user_data    The parastate.
 */
static void mnotify(CURLM *multi, unsigned int notification,
                    CURL *easy, void *user_data)
{
  struct parastate *s = user_data;
  CURLcode result;

  (void)multi;
  (void)easy;

  switch(notification) {
  case CURLMNOTIFY_INFO_READ:
    result = check_finished(s);
    /* remember first failure */
    if(result && !s->result)
      s->result = result;
    break;
  default:
    break;
  }
}

/**
 * @internal
 * @brief Run all transfers in parallel with one multi handle.
 *
 * @param[in] share Share object.
 * @return CURLE_OK, or the first transfer error; CURLE_FAILED_INIT if the
 *         multi handle cannot be set up.
 * @see add_parallel_transfers(), check_finished()
 */
static CURLcode parallel_transfers(CURLSH *share)
{
  CURLcode result;
  struct parastate p;
  struct parastate *s = &p;
  s->share = share;
  s->mcode = CURLM_OK;
  s->result = CURLE_OK;
  s->still_running = 1;
  s->start = curlx_now();
  s->wrapitup = FALSE;
  s->wrapitup_processed = FALSE;
  s->tick = time(NULL);
  s->multi = curl_multi_init();
  if(!s->multi)
    return CURLE_OUT_OF_MEMORY;

  if(TRUE
#ifdef DEBUGBUILD
    && getenv("CURL_QUICK_EXIT")
#endif
    ) {
    /* QUICK_EXIT allows for running threads to be detached and not
     * joined. Preferably in non-debug runs. */
    (void)curl_multi_setopt(s->multi, CURLMOPT_QUICK_EXIT, 1L);
  }
  (void)curl_multi_setopt(s->multi, CURLMOPT_NOTIFYFUNCTION, mnotify);
  (void)curl_multi_setopt(s->multi, CURLMOPT_NOTIFYDATA, s);
  (void)curl_multi_setopt(s->multi, CURLMOPT_MAX_HOST_CONNECTIONS, (long)
                          global->parallel_host);
  (void)curl_multi_notify_enable(s->multi, CURLMNOTIFY_INFO_READ);

  result = add_parallel_transfers(s->multi, s->share,
                                  &s->more_transfers, &s->added_transfers);
  if(result) {
    curl_multi_cleanup(s->multi);
    return result;
  }

#ifdef DEBUGBUILD
  if(global->test_event_based)
#ifdef USE_LIBUV
    return parallel_event(s);
#else
    errorf("Testing --parallel event-based requires libuv");
#endif
  else
#endif

  if(all_added) {
    while(!s->mcode && (s->still_running || s->more_transfers)) {
      /* If stopping prematurely (eg due to a --fail-early condition) then
         signal that any transfers in the multi should abort (via progress
         callback). */
      if(s->wrapitup) {
        if(!s->still_running)
          break;
        if(!s->wrapitup_processed) {
          struct per_transfer *per;
          for(per = transfers; per; per = per->next) {
            if(per->added)
              per->abort = TRUE;
          }
          s->wrapitup_processed = TRUE;
        }
      }
      else if(s->more_transfers) {
        s->result = add_parallel_transfers(s->multi, s->share,
                                           &s->more_transfers,
                                           &s->added_transfers);
        if(s->result)
          break;
      }

      s->mcode = curl_multi_poll(s->multi, NULL, 0, 1000, NULL);
      if(!s->mcode)
        s->mcode = curl_multi_perform(s->multi, &s->still_running);

      progress_meter(s->multi, &s->start, FALSE);
    }

    (void)progress_meter(s->multi, &s->start, TRUE);
  }

  /* Result is the first failed transfer - if there was one. */
  result = s->result;

  /* Make sure to return some kind of error if there was a multi problem */
  if(s->mcode) {
    result = (s->mcode == CURLM_OUT_OF_MEMORY) ? CURLE_OUT_OF_MEMORY :
      /* The other multi errors should never happen, so return
         something suitably generic */
      CURLE_BAD_FUNCTION_ARGUMENT;
  }

  curl_multi_cleanup(s->multi);

  return result;
}

/**
 * @internal
 * @brief Run all transfers one after another.
 *
 * @param[in] share Share object.
 * @return CURLE_OK, the first transfer failure, or CURLE_READ_ERROR when
 *         no transfer could be created.
 * @see parallel_transfers()
 */
static CURLcode serial_transfers(CURLSH *share)
{
  CURLcode returncode = CURLE_OK;
  CURLcode result = CURLE_OK;
  struct per_transfer *per;
  bool added = FALSE;
  bool skipped = FALSE;

  result = create_transfer(share, &added, &skipped);
  if(result)
    return result;
  if(!added) {
    errorf("no transfer performed");
    return CURLE_READ_ERROR;
  }
  for(per = transfers; per;) {
    bool retry;
    uint32_t delay_ms;
    bool bailout = FALSE;
    struct curltime start;

    start = curlx_now();
    if(!per->skip) {
      result = pre_transfer(per);
      if(result)
        break;

      if(global->libcurl) {
        result = easysrc_perform();
        if(result)
          break;
      }

#ifdef DEBUGBUILD
      if(getenv("CURL_FORBID_REUSE"))
        (void)curl_easy_setopt(per->curl, CURLOPT_FORBID_REUSE, 1L);

      if(global->test_duphandle) {
        CURL *dup = curl_easy_duphandle(per->curl);
        curl_easy_cleanup(per->curl);
        per->curl = dup;
        if(!dup) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
        /* a duplicate needs the share re-added */
        (void)curl_easy_setopt(per->curl, CURLOPT_SHARE, share);
      }
      if(global->test_event_based)
        result = curl_easy_perform_ev(per->curl);
      else
#endif
        result = curl_easy_perform(per->curl);
    }

    returncode = post_per_transfer(per, result, &retry, &delay_ms);
    if(retry) {
      curlx_wait_ms(delay_ms);
      continue;
    }

    /* Bail out upon critical errors or --fail-early */
    if(is_fatal_error(returncode) || (returncode && global->fail_early))
      bailout = TRUE;
    else {
      do {
        /* setup the next one before we delete this */
        result = create_transfer(share, &added, &skipped);
        if(result) {
          returncode = result;
          bailout = TRUE;
          break;
        }
      } while(skipped);
    }

    per = del_per_transfer(per);

    if(bailout)
      break;

    if(per && global->ms_per_transfer) {
      /* how long time did the most recent transfer take in number of
         milliseconds */
      timediff_t milli = curlx_timediff_ms(curlx_now(), start);
      if(milli < global->ms_per_transfer) {
        notef("Transfer took %" CURL_FORMAT_CURL_OFF_T " ms, "
              "waits %ldms as set by --rate",
              milli, (long)(global->ms_per_transfer - milli));
        /* The transfer took less time than wanted. Wait a little. */
        curlx_wait_ms((long)(global->ms_per_transfer - milli));
      }
    }
  }
  if(returncode)
    result = returncode;  /* returncode errors have priority */

  if(result)
    single_transfer_cleanup();

  return result;
}

#ifdef _WIN32
/* returns TRUE if using Schannel or if there is an error, passes back result
   in 'resultp' */
/**
 * @internal
 * @brief Check if the TLS backend is Schannel (Windows only).
 *
 * The answer is cached after the first call.
 *
 * @param[out] resultp Result of the backend query.
 * @return TRUE if Schannel is used or an error occurred, else FALSE.
 */
static bool win32_using_schannel(CURLcode *resultp)
{
  static int using_schannel = -1; /* -1 = not checked
                                     0 = nope
                                     1 = yes */
  *resultp = CURLE_OK;
  if(using_schannel == -1) {
    CURL *curl = curl_easy_init();
    /* The TLS backend remains, so keep the info */
    const struct curl_tlssessioninfo *tls_backend_info = NULL;

    if(!curl)
      *resultp = CURLE_OUT_OF_MEMORY;
    else {
      *resultp = curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR,
                                   &tls_backend_info);
      if(!*resultp)
        using_schannel =
          (tls_backend_info->backend == CURLSSLBACKEND_SCHANNEL);
    }
    curl_easy_cleanup(curl);
    if(*resultp)
      return TRUE;
  }
  return using_schannel == 1;
}

/**
 * @internal
 * @brief Find the CA bundle on Windows (Windows only).
 *
 * @param[in,out] config Operation configuration, cacert may be set.
 * @return CURLE_OK or CURLE_OUT_OF_MEMORY.
 */
static CURLcode win32_setup_certs(struct OperationConfig *config)
{
  if(!config->capath && !config->cacert) {
#ifdef CURL_CA_SEARCH_SAFE
    char *cacert = NULL;
    FILE *cafile = tool_execpath("curl-ca-bundle.crt", &cacert);
    if(cafile) {
      curlx_fclose(cafile);
      config->cacert = curlx_strdup(cacert);
      if(!config->cacert)
        return CURLE_OUT_OF_MEMORY;
    }
#elif !defined(CURL_WINDOWS_UWP) && !defined(CURL_DISABLE_CA_SEARCH)
    CURLcode result = FindWin32CACert(config, TEXT("curl-ca-bundle.crt"));
    if(result)
      return result;
#endif
  }
  return CURLE_OK;
}
#else
/**
 * @internal
 * @brief Stubs for non-Windows builds, always succeed or return FALSE.
 */
#define win32_setup_certs(x) CURLE_OK
#define win32_using_schannel(x) FALSE
#endif

/**
 * @internal
 * @brief Set the CA cert locations specified in the environment.
 *
 * For Windows, if no environment-specified file name is found, the CA
 * bundle is searched for in the same places as for libcurl, unless that is
 * disabled. Ignored with --insecure, explicit --cacert/--capath, and
 * when Schannel is the backend.
 *
 * @param[in,out] config Operation configuration, may set cacert/capath.
 * @return CURLE_OK or CURLE_OUT_OF_MEMORY.
 */
static CURLcode cacertpaths(struct OperationConfig *config)
{
  char *env;
  CURLcode result = CURLE_OK;

  if(!feature_ssl || config->cacert || config->capath ||
     (config->insecure_ok && (!config->doh_url || config->doh_insecure_ok)))
    return CURLE_OK;

  if(win32_using_schannel(&result))
    return result;

  env = curl_getenv("CURL_CA_BUNDLE");
  if(env) {
    config->cacert = curlx_strdup(env);
    curl_free(env);
    if(!config->cacert)
      result = CURLE_OUT_OF_MEMORY;
  }
  else {
    env = curl_getenv("SSL_CERT_DIR");
    if(env) {
      config->capath = curlx_strdup(env);
      curl_free(env);
      if(!config->capath)
        result = CURLE_OUT_OF_MEMORY;
    }
    if(!result) {
      env = curl_getenv("SSL_CERT_FILE");
      if(env) {
        config->cacert = curlx_strdup(env);
        curl_free(env);
        if(!config->cacert)
          result = CURLE_OUT_OF_MEMORY;
      }
    }
  }

  if(!result)
    result = win32_setup_certs(config);
  if(result) {
    curlx_safefree(config->capath);
    curlx_safefree(config->cacert);
  }
  return result;
}

/**
 * @internal
 * @brief Set up a transfer for the given config.
 *
 * @param[in,out] config  Operation configuration.
 * @param[in]     share   Share object.
 * @param[out]    added   TRUE if a transfer was created.
 * @param[out]    skipped TRUE if the URL was skipped.
 * @return CURLE_OK, CURLE_FAILED_INIT when no URL was given, or another
 *         setup error.
 */
static CURLcode transfer_per_config(struct OperationConfig *config,
                                    CURLSH *share,
                                    bool *added,
                                    bool *skipped)
{
  CURLcode result;
  *added = FALSE;

  /* Check we have a URL */
  if(!config->url_list || !config->url_list->url) {
    helpf("(%d) no URL specified", CURLE_FAILED_INIT);
    result = CURLE_FAILED_INIT;
  }
  else {
    result = cacertpaths(config);
    if(!result) {
      result = single_transfer(config, share, added, skipped);
      if(!*added || result)
        single_transfer_cleanup();
    }
  }

  return result;
}

/**
 * @internal
 * @brief Get the details and set up a new transfer.
 *
 * Walks the chain of operation configs until one yields a transfer.
 *
 * @param[in]  share   Share object.
 * @param[out] added   TRUE if a transfer was added.
 * @param[out] skipped TRUE if the URL was skipped.
 * @return CURLE_OK or the error from transfer_per_config().
 */
static CURLcode create_transfer(CURLSH *share,
                                bool *added,
                                bool *skipped)
{
  CURLcode result = CURLE_OK;
  *added = FALSE;
  while(global->current) {
    result = transfer_per_config(global->current, share, added, skipped);
    if(!result && !*added) {
      /* when one set is drained, continue to next */
      global->current = global->current->next;
      continue;
    }
    break;
  }
  return result;
}

/**
 * @internal
 * @brief Run all transfers, serially or in parallel, then clean up.
 *
 * @param[in] share  Share object.
 * @param[in] result Result so far; transfers only run if it is CURLE_OK.
 * @return The result of the run.
 * @post Global noprogress/isatty flags are restored and the transfer
 *       list is freed.
 */
static CURLcode run_all_transfers(CURLSH *share,
                                  CURLcode result)
{
  /* Save the values of noprogress and isatty to restore them later on */
  bool orig_noprogress = (bool)global->noprogress;
  bool orig_isatty = (bool)global->isatty;
  struct per_transfer *per;

  /* Time to actually do the transfers */
  if(!result) {
    if(global->parallel)
      result = parallel_transfers(share);
    else
      result = serial_transfers(share);
  }

  /* cleanup if there are any left */
  for(per = transfers; per;) {
    bool retry;
    uint32_t delay;
    CURLcode result2;
    /* No further retries can be performed during final cleanup. */
    per->retry_remaining = 0;
    result2 = post_per_transfer(per, result, &retry, &delay);
    if(!result)
      /* do not overwrite the original error */
      result = result2;

    /* Free list of given URLs */
    clean_getout(per->config);

    per = del_per_transfer(per);
  }

  /* Reset the global config variables */
  global->noprogress = orig_noprogress;
  global->isatty = orig_isatty;

  return result;
}

/**
 * @internal
 * @brief Enable sharing of one kind of data.
 *
 * @param[in] share Share object.
 * @param[in] opt   CURL_LOCK_DATA_* value.
 * @return CURLE_OK (also when unsupported), else CURLE_FAILED_INIT.
 */
static CURLcode share_setopt(CURLSH *share, int opt)
{
  CURLSHcode shres = curl_share_setopt(share, CURLSHOPT_SHARE, opt);
  if(!shres || (shres == CURLSHE_NOT_BUILT_IN))
    return CURLE_OK;
  return CURLE_FAILED_INIT;
}

/**
 * @internal
 * @brief Enable sharing of cookies, DNS, TLS sessions, PSL, HSTS, etc.
 *
 * @param[in] share Share object.
 * @return CURLE_OK, or CURLE_FAILED_INIT.
 */
static CURLcode share_setup(CURLSH *share)
{
  CURLcode result = CURLE_OK;
  int i;
  static int options[7] = {
    CURL_LOCK_DATA_COOKIE,
    CURL_LOCK_DATA_DNS,
    CURL_LOCK_DATA_SSL_SESSION,
    CURL_LOCK_DATA_PSL,
    CURL_LOCK_DATA_HSTS,
    0, /* 5 might be set below */
    0
  };
  /* Running parallel, use the multi connection cache */
  if(!global->parallel)
    options[5] = CURL_LOCK_DATA_CONNECT;
  for(i = 0; !result && options[i]; i++)
    result = share_setopt(share, options[i]);
  return result;
}

/**
 * @brief Run the curl tool.
 *
 * Reads .curlrc, parses arguments, handles help/manual/version requests,
 * sets up the share object and executes every transfer.
 *
 * @param[in] argc Number of arguments.
 * @param[in] argv Arguments (wide characters on Windows Unicode builds).
 * @return CURLE_OK on success, or the CURLcode of the first failure
 *         (CURLE_FAILED_INIT for usage errors, CURLE_READ_ERROR,
 *         CURLE_UNSUPPORTED_PROTOCOL, CURLE_OUT_OF_MEMORY).
 * @pre The global configuration has been initialised.
 * @post The caller must call globalconf_free().
 */
CURLcode operate(int argc, argv_item_t argv[])
{
  CURLcode result = CURLE_OK;
  const char *first_arg;
  char *curlrc_path = NULL;
  bool found_curlrc = FALSE;

  first_arg = argc > 1 ? convert_tchar_to_UTF8(argv[1]) : NULL;

#ifdef HAVE_SETLOCALE
  /* Override locale for number parsing (only) */
  setlocale(LC_ALL, "");
  setlocale(LC_NUMERIC, "C");
#endif

  /* Parse .curlrc if necessary */
  if((argc == 1) ||
     (first_arg && strncmp(first_arg, "-q", 2) &&
      strcmp(first_arg, "--disable"))) {
    if(!parseconfig(NULL, CONFIG_MAX_LEVELS, &curlrc_path))
      found_curlrc = TRUE;

    /* If we had no arguments then make sure a URL was specified in .curlrc */
    if((argc < 2) && (!global->first->url_list)) {
      helpf(NULL);
      result = CURLE_FAILED_INIT;
    }
  }

  unicodefree(CURL_UNCONST(first_arg));

  if(!result) {
    /* Parse the command line arguments */
    ParameterError err = parse_args(argc, argv);
    if(found_curlrc) {
      /* After parse_args so notef knows the verbosity */
      notef("Read config file from '%s'", curlrc_path);
    }
    if(err) {
      result = CURLE_OK;

      /* Check if we were asked for the help */
      if(err == PARAM_HELP_REQUESTED)
        ; /* already done */
      /* Check if we were asked for the manual */
      else if(err == PARAM_MANUAL_REQUESTED) {
#ifdef USE_MANUAL
        hugehelp();
#else
        warnf("built-in manual was disabled at build-time");
#endif
      }
      /* Check if we were asked for the version information */
      else if(err == PARAM_VERSION_INFO_REQUESTED)
        tool_version_info();
      /* Check if we were asked to list the SSL engines */
      else if(err == PARAM_ENGINES_REQUESTED)
        tool_list_engines();
      /* Check if we were asked to dump the embedded CA bundle */
      else if(err == PARAM_CA_EMBED_REQUESTED) {
#ifdef CURL_CA_EMBED
        curl_mprintf("%s", curl_ca_embed);
#endif
      }
      else if(err == PARAM_LIBCURL_UNSUPPORTED_PROTOCOL)
        result = CURLE_UNSUPPORTED_PROTOCOL;
      else if(err == PARAM_READ_ERROR)
        result = CURLE_READ_ERROR;
      else
        result = CURLE_FAILED_INIT;
    }
    else {
      if(global->libcurl) {
        /* Initialize the libcurl source output */
        result = easysrc_init();
      }

      /* Perform the main operations */
      if(!result) {
        size_t count = 0;
        struct OperationConfig *operation = global->first;
        CURLSH *share = curl_share_init();
        if(!share) {
          if(global->libcurl) {
            /* Cleanup the libcurl source output */
            easysrc_cleanup();
          }
          result = CURLE_OUT_OF_MEMORY;
        }

        if(!result)
          result = share_setup(share);

        if(!result && global->ssl_sessions && feature_ssls_export)
          result = tool_ssls_load(global->first, share,
                                  global->ssl_sessions);

        if(!result) {
          /* Get the required arguments for each operation */
          do {
            result = get_args(operation, count++);

            operation = operation->next;
          } while(!result && operation);

          if(!result) {
            /* Set the current operation pointer */
            global->current = global->first;

            /* now run! */
            result = run_all_transfers(share, result);

            if(global->ssl_sessions && feature_ssls_export) {
              CURLcode r2 = tool_ssls_save(global->first, share,
                                           global->ssl_sessions);
              if(r2 && !result)
                result = r2;
            }
          }
        }

        curl_share_cleanup(share);
        if(global->libcurl) {
          /* Cleanup the libcurl source output */
          easysrc_cleanup();

          /* Dump the libcurl code if previously enabled */
          dumpeasysrc();
        }
      }
      else
        errorf("out of memory");
    }
  }
  curlx_free(curlrc_path);
  varcleanup();

  return result;
}
