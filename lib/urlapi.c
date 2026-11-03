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
 * @brief Implementation of the URL API (CURLU handle, curl_url_*()).
 *
 * This file implements the public libcurl URL parsing and manipulation API:
 * curl_url(), curl_url_dup(), curl_url_cleanup(), curl_url_get() and
 * curl_url_set(). A CURLU handle stores the individual components of a URL
 * (scheme, user, password, options, host, zone id, port, path, query and
 * fragment) as separately allocated strings so each can be read or replaced
 * independently, then re-assembled into a full URL on demand.
 *
 * Besides the public API it contains the helpers used by the rest of the
 * library to validate hostnames, normalize IPv4/IPv6 addresses, URL-encode
 * and decode parts, resolve relative references (RFC 3986 section 5.2) and
 * remove dot segments.
 *
 * @note Strings handed out by curl_url_get() are allocated and must be
 *       released by the caller with curl_free().
 * @warning A CURLU handle is not thread-safe. Callers must serialize access
 *          to one handle; independent handles may be used concurrently.
 * @see https://datatracker.ietf.org/doc/html/rfc3986
 * @see https://curl.se/libcurl/c/libcurl-url.html
 *
 * @defgroup urlapi URL API
 * @brief Parsing, validation and (re)assembly of URLs held in a CURLU handle.
 * @{
 */
#include "curl_setup.h"

#include "urldata.h"
#include "urlapi-int.h"
#include "strcase.h"
#include "url.h"
#include "escape.h"
#include "curlx/inet_pton.h"
#include "curlx/inet_ntop.h"
#include "curlx/strdup.h"
#include "idn.h"
#include "curlx/strparse.h"
#include "curl_memrchr.h"

#ifdef _WIN32
/**
 * @def STARTS_WITH_DRIVE_PREFIX
 * @brief Test whether a string begins with a Windows drive prefix.
 *
 * Matches an ASCII letter followed by a colon, for example "c:" in "c:foo".
 * Only defined on Windows builds.
 *
 * @param[in] str NUL-terminated string, at least two readable bytes.
 * @return Non-zero when the string starts with "<letter>:".
 */
#define STARTS_WITH_DRIVE_PREFIX(str)        \
  ((('a' <= (str)[0] && (str)[0] <= 'z') ||  \
    ('A' <= (str)[0] && (str)[0] <= 'Z')) && \
   ((str)[1] == ':'))
#endif

/**
 * @def STARTS_WITH_URL_DRIVE_PREFIX
 * @brief Test whether a URL path starts with a Windows drive prefix.
 *
 * Matches an ASCII letter, then ':' or '|', then a slash, a backslash or the
 * terminating NUL. The '|' variant is the legacy file: URL spelling.
 *
 * @param[in] str NUL-terminated string, at least three readable bytes
 *                (the third is only read if the first two match).
 * @return Non-zero when the prefix matches.
 */
#define STARTS_WITH_URL_DRIVE_PREFIX(str)                  \
  ((('a' <= (str)[0] && (str)[0] <= 'z') ||                \
    ('A' <= (str)[0] && (str)[0] <= 'Z')) &&               \
   ((str)[1] == ':' || (str)[1] == '|') &&                 \
   ((str)[2] == '/' || (str)[2] == '\\' || (str)[2] == 0))

/**
 * @def MAX_SCHEME_LEN
 * @brief Maximum accepted scheme length in bytes (without the terminator).
 *
 * The scheme is never URL encoded; 40 is longer than any scheme libcurl
 * supports.
 */
#define MAX_SCHEME_LEN 40
/**
 * @def MAX_ZONEID_LEN
 * @brief Size of the buffer used to hold an IPv6 zone id, including the NUL.
 */
#define MAX_ZONEID_LEN 16

/**
 * @def AF_INET6
 * @brief Fallback address family value when IPv6 support is disabled.
 *
 * If USE_IPV6 is disabled, IPv6 addresses must still be parsed, so make
 * sure there is _some_ value for AF_INET6 without polluting the fake value
 * everywhere else.
 */
#if !defined(USE_IPV6) && !defined(AF_INET6)
#define AF_INET6 (AF_INET + 1)
#endif

/**
 * @def DEFAULT_SCHEME
 * @brief Scheme assumed when CURLU_DEFAULT_SCHEME is set and none is given.
 */
#define DEFAULT_SCHEME "https"

/**
 * @brief Release every string owned by a URL handle.
 * @internal
 *
 * Frees scheme, user, password, options, host, zone id, path, query and
 * fragment. The password is wiped before it is freed. The handle structure
 * itself is not freed and the pointers are not reset, so the caller must
 * either free or overwrite the struct afterwards.
 *
 * @param[in,out] u URL handle whose members are released; must not be NULL.
 * @warning The members are left dangling. Do not use @p u again without
 *          re-initializing it (memset or struct assignment).
 * @see curl_url_cleanup()
 */
static void free_urlhandle(struct Curl_URL *u)
{
  curlx_free(u->scheme);
  curlx_free(u->user);
  curlx_strzero(u->password);
  curlx_free(u->password);
  curlx_free(u->options);
  curlx_free(u->host);
  curlx_free(u->zoneid);
  curlx_free(u->path);
  curlx_free(u->query);
  curlx_free(u->fragment);
}

/**
 * @brief Find the separator at the end of the hostname.
 * @internal
 *
 * Locates the first '/' or '?' after the authority start, which is how
 * "http://www.example.com?id=2380" is split. If "//" is present the search
 * starts after it, otherwise from the beginning of the string.
 *
 * @param[in] url NUL-terminated URL (or URL-like string); must not be NULL.
 * @return Pointer into @p url at the '/' or '?' separator, or at the
 *         terminating NUL when there is none. Never NULL.
 */
static const char *find_host_sep(const char *url)
{
  /* Find the start of the hostname */
  const char *sep = strstr(url, "//");
  if(!sep)
    sep = url;
  else
    sep += 2;

  /* Find first / or ? */
  while(*sep && *sep != '/' && *sep != '?')
    sep++;

  return sep;
}

/**
 * @def cc2cu
 * @brief Convert a CURLcode to a CURLUcode.
 *
 * @param[in] x A CURLcode result.
 * @return CURLUE_TOO_LARGE for CURLE_TOO_LARGE, otherwise
 *         CURLUE_OUT_OF_MEMORY.
 * @note Only valid for the error codes dynbuf operations can produce.
 */
#define cc2cu(x) \
  ((x) == CURLE_TOO_LARGE ? CURLUE_TOO_LARGE : CURLUE_OUT_OF_MEMORY)

/**
 * @brief URL-encode what has to be encoded in a URL string into a dynbuf.
 * @internal
 *
 * Writes the input to @p o and encodes spaces, control bytes (< 0x20) and
 * bytes >= 0x7f. The function re-encodes: already percent-encoded bytes are
 * left as-is and only what @b has to be encoded is touched, except that
 * lowercase hex digits in a valid %xx sequence are uppercased to normalize.
 * Illegal percent sequences are left untouched.
 *
 * URL encoding is skipped for the hostname part (when @p relative is FALSE),
 * otherwise IDN resolution would fail.
 *
 * @param[in,out] o        Output buffer; data is appended.
 * @param[in]     url      Input bytes (need not be NUL-terminated).
 * @param[in]     len      Number of bytes in @p url.
 * @param[in]     relative TRUE if @p url is a relative reference without
 *                         scheme and authority; FALSE if the leading
 *                         "scheme://host" part must be copied untouched.
 * @param[in]     query    One of QUERY_NO, QUERY_NOT_YET or QUERY_YES. Tells
 *                         whether this is a query part (spaces become '+'),
 *                         or whether a '?' may switch to a query part.
 * @return CURLUE_OK on success.
 * @return CURLUE_TOO_LARGE if the buffer limit is exceeded.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @post On error @p o may hold partial output; the caller frees it.
 * @note Unit tested by unit test 1675.
 */
UNITTEST CURLUcode urlencode_str(struct dynbuf *o, const char *url,
                                 size_t len, bool relative,
                                 unsigned int query);
UNITTEST CURLUcode urlencode_str(struct dynbuf *o, const char *url,
                                 size_t len, bool relative,
                                 unsigned int query)
{
  /* we must add this with whitespace-replacing */
  const unsigned char *iptr;
  const unsigned char *host_sep = (const unsigned char *)url;
  CURLcode result = CURLE_OK;

  DEBUGASSERT((query >= QUERY_NO) && (query <= QUERY_YES));

  if(!relative) {
    size_t n;
    /* Non-relative input: copy "scheme://host" verbatim up to the
       first "/" or "?" and encode only the rest. */
    host_sep = (const unsigned char *)find_host_sep(url);

    /* output the first piece as-is */
    n = (const char *)host_sep - url;
    result = curlx_dyn_addn(o, url, n);
    len -= n;
  }

  /* Walk the input, handling one special byte or one run of plain
     bytes per iteration. */
  for(iptr = host_sep; len && !result;) {
    /* Space: "%20" outside queries, "+" inside a query. */
    if(*iptr == ' ') {
      if(query != QUERY_YES)
        result = curlx_dyn_addn(o, "%20", 3);
      else
        result = curlx_dyn_addn(o, "+", 1);
      iptr++;
      len--;
    }
    else if((*iptr < ' ') || (*iptr >= 0x7f)) {
      /* Control byte or byte >= 0x7f: percent-encode it. */
      unsigned char out[3] = { '%' };
      Curl_hexbyte(&out[1], *iptr);
      result = curlx_dyn_addn(o, out, 3);
      iptr++;
      len--;
    }
    else if(*iptr == '%' && (len >= 3) &&
            ISXDIGIT(iptr[1]) && ISXDIGIT(iptr[2]) &&
            (ISLOWER(iptr[1]) || ISLOWER(iptr[2]))) {
      /* uppercase it */
      unsigned char hex = (unsigned char)((curlx_hexval(iptr[1]) << 4) |
                                          curlx_hexval(iptr[2]));
      unsigned char out[3] = { '%' };
      Curl_hexbyte(&out[1], hex);
      result = curlx_dyn_addn(o, out, 3);
      iptr += 3;
      len -= 3;
    }
    else {
      /* Plain run: copy as many unremarkable bytes as possible at once. */
      const unsigned char *start = iptr;
      while(len) {
        if(*iptr == ' ' || *iptr < ' ' || *iptr >= 0x7f)
          break;
        if(*iptr == '%' && (len >= 3) &&
           ISXDIGIT(iptr[1]) && ISXDIGIT(iptr[2]) &&
           (ISLOWER(iptr[1]) || ISLOWER(iptr[2])))
          break;
        /* The first "?" turns the rest of the string into the query part. */
        if(*iptr == '?') {
          if(query == QUERY_NOT_YET) {
            iptr++;
            len--;
            query = QUERY_YES;
            break;
          }
        }
        iptr++;
        len--;
      }
      result = curlx_dyn_addn(o, (const char *)start, (size_t)(iptr - start));
    }
  }

  if(result)
    return cc2cu(result);
  return CURLUE_OK;
}

/**
 * @brief Tell whether a URL is absolute and return its scheme length.
 *
 * A URL is absolute when it starts with a syntactically valid scheme
 * (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )) followed by a colon. When
 * @p guess_scheme is TRUE the URL might be given without any scheme, so
 * the colon must additionally be followed by '/' (otherwise "data:80"
 * would be a host and port, not a scheme). On Windows a drive prefix such
 * as "c:" is never treated as a scheme in guessing mode.
 *
 * @param[in]  url          NUL-terminated URL to inspect.
 * @param[out] buf          Optional. Receives the lowercased scheme,
 *                          NUL-terminated. Always set to a defined value
 *                          (empty string) when not NULL.
 * @param[in]  buflen       Size of @p buf; must be larger than
 *                          MAX_SCHEME_LEN when @p buf is set.
 * @param[in]  guess_scheme TRUE if the URL may lack a scheme.
 * @return Length of the scheme (excluding the colon) if the URL is
 *         absolute, 0 if it is relative.
 * @pre If @p buf is not NULL then @p buflen > MAX_SCHEME_LEN.
 */
size_t Curl_is_absolute_url(const char *url, char *buf, size_t buflen,
                            bool guess_scheme)
{
  size_t i = 0;
  DEBUGASSERT(!buf || (buflen > MAX_SCHEME_LEN));
  (void)buflen; /* only used in debug-builds */
  if(buf)
    buf[0] = 0; /* always leave a defined value in buf */
#ifdef _WIN32
  if(guess_scheme && STARTS_WITH_DRIVE_PREFIX(url))
    return 0;
#endif
  /* Collect the scheme characters, lowercasing them into buf. */
  if(ISALPHA(url[0])) {
    if(buf)
      buf[0] = Curl_raw_tolower(url[0]);
    for(i = 1; i < MAX_SCHEME_LEN; ++i) {
      char s = url[i];
      if(s && (ISALNUM(s) || (s == '+') || (s == '-') || (s == '.'))) {
        if(buf)
          buf[i] = Curl_raw_tolower(s);
      }
      else {
        break;
      }
    }
  }
  if(i && (url[i] == ':') && ((url[i + 1] == '/') || !guess_scheme)) {
    /* If this does not guess scheme, the scheme always ends with the colon so
       that this also detects data: URLs etc. In guessing mode, data: could
       be the hostname "data" with a specified port number. */

    /* the length of the scheme is the name part only */
    size_t len = i;
    if(buf)
      buf[i] = 0;
    return len;
  }
  if(buf)
    buf[0] = 0;
  return 0;
}

/**
 * @brief Scan for bytes that are not allowed in a URL component.
 * @internal
 *
 * Rejects bytes <= 31 and 127. The space (0x20) is also rejected unless
 * CURLU_ALLOW_SPACE is present in @p flags.
 *
 * @param[in] input Bytes to scan.
 * @param[in] n     Number of bytes to scan.
 * @param[in] flags CURLU_* flags; only CURLU_ALLOW_SPACE is examined.
 * @return TRUE if a forbidden byte was found, FALSE if the data is clean.
 */
static bool badoctets(const char *input, size_t n, int flags)
{
  const uint8_t *p = (const unsigned char *)input;
  const uint8_t control = flags & CURLU_ALLOW_SPACE ? 0x1f : 0x20;
  while(n--) {
    if(*p <= control || *p == 127)
      return TRUE;
    p++;
  }
  return FALSE;
}

/**
 * @brief Extract user, password and options from an authority string.
 * @internal
 *
 * Parses the login details of the form
 * "[user[:password][;options]]\@hostname" and stores them in the handle,
 * leaving the hostname part to the caller. Options are only parsed for
 * schemes that set PROTOPT_URLOPTIONS. Previously stored login parts are
 * replaced. On failure all login members of the handle are cleared.
 *
 * @param[in,out] u               URL handle receiving user, password and
 *                                options; u->scheme (if set) selects the
 *                                scheme handler.
 * @param[in]     login           Start of the authority (not necessarily
 *                                NUL-terminated).
 * @param[in]     len             Length of @p login in bytes.
 * @param[in]     flags           CURLU_* flags (CURLU_DISALLOW_USER,
 *                                CURLU_ALLOW_SPACE).
 * @param[out]    hostname_offset Offset in @p login where the hostname
 *                                starts (0 if there is no at-sign).
 * @return CURLUE_OK on success, also when no login info is present.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @return CURLUE_USER_NOT_ALLOWED if CURLU_DISALLOW_USER is set and a user
 *         name is present.
 * @return CURLUE_BAD_USER or CURLUE_BAD_PASSWORD on forbidden bytes.
 * @return CURLUE_MALFORMED_INPUT on forbidden bytes in the options.
 * @warning The password is securely wiped before it is freed.
 * @note Unit tested by unit test 1675.
 */
UNITTEST CURLUcode parse_hostname_login(struct Curl_URL *u,
                                        const char *login,
                                        size_t len,
                                        unsigned int flags,
                                        size_t *hostname_offset);
UNITTEST CURLUcode parse_hostname_login(struct Curl_URL *u,
                                        const char *login,
                                        size_t len,
                                        unsigned int flags,
                                        size_t *hostname_offset)
{
  CURLUcode ures = CURLUE_OK;
  CURLcode result;
  char *userp = NULL;
  char *passwdp = NULL;
  char *optionsp = NULL;
  const struct Curl_scheme *h = NULL;

  /* At this point, we assume all the other special cases have been taken
   * care of, so the host is at most
   *
   *   [user[:password][;options]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */
  const char *ptr;

  DEBUGASSERT(login);

  *hostname_offset = 0;
  ptr = memchr(login, '@', len);
  if(!ptr)
    goto out;

  /* We will now try to extract the
   * possible login information in a string like:
   * ftp://user:password@ftp.site.example:8021/README */
  ptr++;

  /* if this is a known scheme, get some details */
  if(u->scheme)
    h = Curl_get_scheme(u->scheme);

  /* We could use the login information in the URL so extract it. Only parse
     options if the handler says we should. Note that 'h' might be NULL! */
  result = Curl_parse_login_details(login, ptr - login - 1,
                                    &userp, &passwdp,
                                    (h && (h->flags & PROTOPT_URLOPTIONS)) ?
                                    &optionsp : NULL);
  if(result) {
    /* the only possible error from Curl_parse_login_details is out of
       memory: */
    ures = CURLUE_OUT_OF_MEMORY;
    goto out;
  }

  if(userp) {
    if(flags & CURLU_DISALLOW_USER) {
      /* Option DISALLOW_USER is set and URL contains username. */
      ures = CURLUE_USER_NOT_ALLOWED;
      goto out;
    }
    curlx_free(u->user);
    u->user = userp;
  }

  if(passwdp) {
    curlx_strzero(u->password);
    curlx_free(u->password);
    u->password = passwdp;
  }

  if(optionsp) {
    curlx_free(u->options);
    u->options = optionsp;
  }

  if(userp && badoctets(userp, strlen(userp), flags))
    ures = CURLUE_BAD_USER;
  else if(passwdp && badoctets(passwdp, strlen(passwdp), flags))
    ures = CURLUE_BAD_PASSWORD;
  else if(optionsp && badoctets(optionsp, strlen(optionsp), flags))
    ures = CURLUE_MALFORMED_INPUT;

  userp = passwdp = optionsp = NULL;

  if(!ures) {
    /* the hostname starts at this offset */
    *hostname_offset = ptr - login;
    return CURLUE_OK;
  }

out:

  curlx_free(userp);
  curlx_strzero(passwdp);
  curlx_free(passwdp);
  curlx_free(optionsp);
  curlx_safefree(u->user);
  curlx_strzero(u->password);
  curlx_safefree(u->password);
  curlx_safefree(u->options);

  return ures;
}

/**
 * @brief Split an optional port number off a hostname buffer.
 * @internal
 *
 * Handles both "host:port" and RFC 2732 style "[v6addr]:port". The host
 * buffer is truncated so it ends before the colon, and u->portnum and
 * u->port_present are set. A colon with no digits after it is ignored (the
 * default port is used) to match Firefox, Chrome and Safari, but only if the
 * URL has a scheme; without one it is an error so that something looking
 * like a scheme does not work.
 *
 * @param[in,out] u          URL handle receiving the port.
 * @param[in,out] host       Host buffer, trimmed in place to the name only.
 * @param[in]     has_scheme TRUE if the URL has (or was given) a scheme.
 * @return CURLUE_OK on success (including no port).
 * @return CURLUE_BAD_IPV6 if a leading '[' has no closing ']'.
 * @return CURLUE_BAD_PORT_NUMBER for a malformed or out of range (> 65535)
 *         port, or garbage after a bracketed address.
 * @return CURLUE_BACKSLASH if a backslash follows the colon or the port.
 * @post u->portnum is 0 and u->port_present FALSE unless a port was parsed.
 * @note Unit tested by unit test 1653.
 */
UNITTEST CURLUcode parse_port(struct Curl_URL *u, struct dynbuf *host,
                              bool has_scheme);
UNITTEST CURLUcode parse_port(struct Curl_URL *u, struct dynbuf *host,
                              bool has_scheme)
{
  const char *portptr;
  const char *hostname = curlx_dyn_ptr(host);
  /*
   * Find the end of an IPv6 address on the ']' ending bracket.
   */
  u->portnum = 0;
  u->port_present = FALSE;
  if(hostname[0] == '[') {
    portptr = memchr(hostname + 1, ']', curlx_dyn_len(host) - 1);
    if(!portptr)
      return CURLUE_BAD_IPV6;
    portptr++;
    /* this is a RFC2732-style specified IP-address */
    if(*portptr) {
      if(*portptr != ':')
        return CURLUE_BAD_PORT_NUMBER;
    }
    else
      portptr = NULL;
  }
  else
    portptr = memchr(hostname, ':', curlx_dyn_len(host));

  if(portptr) {
    curl_off_t port;
    size_t keep = portptr - hostname;
    int rc;

    /* Browser behavior adaptation. If there is a colon with no digits after,
       cut off the name there which makes us ignore the colon and use the
       default port. Firefox, Chrome and Safari all do that.

       Do not do it if the URL has no scheme, to make something that looks like
       a scheme not work! */
    curlx_dyn_setlen(host, keep);
    portptr++;
    if(!*portptr)
      return has_scheme ? CURLUE_OK : CURLUE_BAD_PORT_NUMBER;
    if(*portptr == '\\')
      return CURLUE_BACKSLASH;
    rc = curlx_str_number(&portptr, &port, 0xffff);
    if(rc)
      return CURLUE_BAD_PORT_NUMBER;
    else if(*portptr == '\\')
      return CURLUE_BACKSLASH;
    else if(*portptr)
      return CURLUE_BAD_PORT_NUMBER;

    u->portnum = (uint16_t)port;
    u->port_present = TRUE;
  }

  return CURLUE_OK;
}

/**
 * @brief Lookup table of bytes that are invalid in a hostname.
 *
 * Indexed by the byte value; a non-zero entry marks a byte that must not
 * appear in a hostname. All control bytes are rejected, as are space and
 * these characters: / : # ? ! @ { } [ ] \ $ ' " ^ ` * < > = ; , + & ( ) %
 * and |. Bytes >= 0x80 are outside the table and must be checked by the
 * caller if relevant.
 */
static const bool invalid_host_char[256] = {
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x00-0x0F */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x10-0x1F */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, /* 0x20-0x2F */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, /* 0x30-0x3F */
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40-0x4F */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, /* 0x50-0x5F */
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x60-0x6F */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1  /* 0x70-0x7F */
};

/**
 * @brief Validate and normalize a bracketed IPv6 address in place.
 * @internal
 *
 * Assumes @p hostname starts with '['. Checks that only valid IPv6
 * characters are used, extracts an optional "%zoneid" into u->zoneid,
 * and rewrites the address in its canonical compressed text form. The
 * buffer is only ever shortened.
 *
 * @param[in,out] u        URL handle; u->zoneid is set if a zone id exists.
 * @param[in,out] hostname Host text starting with '[', modified in place.
 * @param[in]     hlen     Length of @p hostname in bytes.
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_IPV6 for a too short, malformed or unparsable address
 *         or a bad zone id.
 * @return CURLUE_OUT_OF_MEMORY if the zone id cannot be allocated.
 * @pre *hostname == '['.
 * @note Unit tested by unit test 1675.
 */
UNITTEST CURLUcode ipv6_parse(struct Curl_URL *u, char *hostname,
                              size_t hlen);
UNITTEST CURLUcode ipv6_parse(struct Curl_URL *u, char *hostname,
                              size_t hlen) /* length of hostname */
{
  size_t len;
  DEBUGASSERT(*hostname == '[');
  if(hlen < 4) /* '[::]' is the shortest possible valid string */
    return CURLUE_BAD_IPV6;
  hostname++;
  hlen -= 2;

  /* only valid IPv6 letters are ok */
  len = strspn(hostname, "0123456789abcdefABCDEF:.");

  if(hlen != len) {
    hlen = len;
    if(hostname[len] == '%') {
      /* this could now be '%[zone id]' */
      char zoneid[MAX_ZONEID_LEN];
      int i = 0;
      char *h = &hostname[len + 1];
      while(!invalid_host_char[(unsigned char)*h] && (*h != ']') &&
            (i < (MAX_ZONEID_LEN - 1)))
        zoneid[i++] = *h++;
      if(!i || (']' != *h))
        return CURLUE_BAD_IPV6;
      zoneid[i] = 0;
      u->zoneid = curlx_strdup(zoneid);
      if(!u->zoneid)
        return CURLUE_OUT_OF_MEMORY;
      hostname[len] = ']'; /* insert end bracket */
      hostname[len + 1] = 0; /* terminate the hostname */
    }
    else
      return CURLUE_BAD_IPV6;
    /* hostname is fine */
  }

  /* Normalize the IPv6 address */
  {
    char dest[16]; /* fits a binary IPv6 address */
    hostname[hlen] = 0; /* end the address there */
    if(curlx_inet_pton(AF_INET6, hostname, dest) != 1)
      return CURLUE_BAD_IPV6;
    if(!curlx_inet_ntop(AF_INET6, dest, hostname, hlen + 1)) {
      hlen = strlen(hostname); /* might be shorter now */
      hostname[hlen + 1] = 0;
    }
    hostname[hlen] = ']'; /* restore ending bracket */
  }
  return CURLUE_OK;
}

/**
 * @brief Check that a name is a syntactically acceptable hostname.
 *
 * Rejects any byte flagged in invalid_host_char, more than one trailing
 * dot, and a single lone dot.
 *
 * @param[in] hostname Hostname text (need not be NUL-terminated).
 * @param[in] hlen     Length of @p hostname in bytes.
 * @return CURLUE_OK if the name is acceptable.
 * @return CURLUE_BAD_HOSTNAME otherwise.
 * @pre The input is a confirmed hostname, never an IPv6 address.
 */
CURLUcode Curl_hostname_check(const char *hostname, size_t hlen)
{
  size_t i;
  for(i = 0; i < hlen; i++) {
    if(invalid_host_char[(unsigned char)hostname[i]])
      return CURLUE_BAD_HOSTNAME;
  }
  if((hlen >= 2) &&
     (hostname[hlen - 1] == '.') && (hostname[hlen - 2] == '.'))
    /* more than one trailing dot is not allowed */
    return CURLUE_BAD_HOSTNAME;
  else if((hlen == 1) && (hostname[0] == '.'))
    /* a single dot alone is not allowed */
    return CURLUE_BAD_HOSTNAME;
  return CURLUE_OK;
}

/**
 * @brief Check a hostname that may also be an IPv6 address.
 * @internal
 *
 * @param[in,out] u        URL handle (receives the zone id for IPv6).
 * @param[in,out] hostname Host text, possibly '['-prefixed.
 * @param[in]     hlen     Length of @p hostname in bytes.
 * @return CURLUE_NO_HOST if @p hlen is zero.
 * @return The result of ipv6_parse() for a '[' prefixed name.
 * @return Otherwise the result of Curl_hostname_check().
 */
static CURLUcode hostname_check6(struct Curl_URL *u, char *hostname,
                                 size_t hlen) /* length of hostname */
{
  DEBUGASSERT(hostname);

  if(!hlen)
    return CURLUE_NO_HOST;
  else if(hostname[0] == '[')
    return ipv6_parse(u, hostname, hlen);

  return Curl_hostname_check(hostname, hlen);
}

/**
 * @brief Normalize a numerical IPv4 host to plain dotted decimal.
 * @internal
 *
 * Handles partial IPv4 numerical addresses and different bases, like
 * "16843009", "0x7f", "0x7f.1" and "0177.1.1.1". The normalized version of
 * the input replaces the buffer content as four decimal integers. A single
 * dot following the numerical address is accepted and swallowed as if it
 * was never there.
 *
 * If the input is syntactically wrong as IPv4, or any part is too big,
 * the buffer is left alone and HOST_NAME is returned.
 *
 * @param[in,out] host Host buffer; rewritten on HOST_IPV4.
 * @return HOST_NAME if the input is not a numerical IPv4 address.
 * @return HOST_IPV4 if it was and the buffer was normalized.
 * @return HOST_ERROR on out of memory.
 * @note Unit tested by unit test 1675.
 */
UNITTEST int ipv4_normalize(struct dynbuf *host);
UNITTEST int ipv4_normalize(struct dynbuf *host)
{
  bool done = FALSE;
  int n = 0;
  const char *c = curlx_dyn_ptr(host);
  unsigned int parts[4] = { 0, 0, 0, 0 };
  CURLcode result = CURLE_OK;

  if(!ISDIGIT(*c))
    return HOST_NAME;

  while(!done) {
    int rc;
    curl_off_t l;
    /* Parse one component, honoring 0x (hex) and leading 0 (octal). */
    if(*c == '0') {
      if((c[1] | 0x20) == 'x') {
        c += 2; /* skip the prefix */
        rc = curlx_str_hex(&c, &l, UINT_MAX);
        if(rc)
          return HOST_NAME;
      }
      else
        rc = curlx_str_octal(&c, &l, UINT_MAX);
    }
    else
      rc = curlx_str_number(&c, &l, UINT_MAX);

    if(rc) {
      if(!n || (rc != STRE_NO_NUM) || *c)
        return HOST_NAME;
      n--;
    }
    else
      parts[n] = (unsigned int)l;

    switch(*c) {
    case '.':
      if(n == 3) {
        if(c[1])
          /* something follows this dot */
          return HOST_NAME;
        done = TRUE;
      }
      else {
        n++;
        c++;
      }
      break;

    case '\0':
      done = TRUE;
      break;

    default:
      return HOST_NAME;
    }
  }

  /* Re-assemble according to how many components were given: the last
     component fills all the remaining bytes. */
  switch(n) {
  case 0: /* a -- 32 bits */
    curlx_dyn_reset(host);

    result = curlx_dyn_addf(host, "%u.%u.%u.%u",
                            (parts[0] >> 24),
                            ((parts[0] >> 16) & 0xff),
                            ((parts[0] >> 8) & 0xff),
                            (parts[0] & 0xff));
    break;
  case 1: /* a.b -- 8.24 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xffffff))
      return HOST_NAME;
    curlx_dyn_reset(host);
    result = curlx_dyn_addf(host, "%u.%u.%u.%u",
                            parts[0],
                            ((parts[1] >> 16) & 0xff),
                            ((parts[1] >> 8) & 0xff),
                            (parts[1] & 0xff));
    break;
  case 2: /* a.b.c -- 8.8.16 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xffff))
      return HOST_NAME;
    curlx_dyn_reset(host);
    result = curlx_dyn_addf(host, "%u.%u.%u.%u",
                            parts[0],
                            parts[1],
                            ((parts[2] >> 8) & 0xff),
                            (parts[2] & 0xff));
    break;
  case 3: /* a.b.c.d -- 8.8.8.8 bits */
    if((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff) ||
       (parts[3] > 0xff))
      return HOST_NAME;
    curlx_dyn_reset(host);
    result = curlx_dyn_addf(host, "%u.%u.%u.%u",
                            parts[0],
                            parts[1],
                            parts[2],
                            parts[3]);
    break;
  }
  if(result)
    return HOST_ERROR;
  return HOST_IPV4;
}

/**
 * @brief Replace the host content with its URL decoded version if needed.
 * @internal
 *
 * Does nothing if the host holds no '%'. Control bytes in the decoded
 * result are rejected.
 *
 * @param[in,out] host Host buffer, replaced in place when decoded.
 * @return CURLUE_OK on success or when nothing needed decoding.
 * @return CURLUE_BAD_HOSTNAME if decoding fails or yields control bytes.
 * @return CURLUE_TOO_LARGE or CURLUE_OUT_OF_MEMORY on buffer errors.
 */
static CURLUcode urldecode_host(struct dynbuf *host)
{
  const char *per;
  const char *hostname = curlx_dyn_ptr(host);
  per = memchr(hostname, '%', curlx_dyn_len(host));
  if(!per)
    /* nothing to decode */
    return CURLUE_OK;
  else {
    /* encoded */
    size_t dlen;
    char *decoded;
    CURLcode result = Curl_urldecode(hostname, 0, &decoded, &dlen,
                                     REJECT_CTRL);
    if(result)
      return CURLUE_BAD_HOSTNAME;
    curlx_dyn_reset(host);
    result = curlx_dyn_addn(host, decoded, dlen);
    curlx_free(decoded);
    if(result)
      return cc2cu(result);
  }

  return CURLUE_OK;
}

/**
 * @brief Parse an authority: login, host and port.
 * @internal
 *
 * Strips user, password and options (see parse_hostname_login()), appends
 * the hostname to @p host, splits off the port, URL-decodes the name and
 * validates it as an IPv6 address, normalized IPv4 address or hostname.
 *
 * @param[in,out] u          URL handle receiving login and port data.
 * @param[in]     auth       Authority text (not NUL-terminated).
 * @param[in]     authlen    Length of @p auth in bytes.
 * @param[in]     flags      CURLU_* flags.
 * @param[in,out] host       Initialized dynbuf that receives the hostname.
 * @param[in]     has_scheme TRUE if the URL has a scheme.
 * @return CURLUE_OK on success, otherwise the error from the failing step:
 *         CURLUE_NO_HOST, CURLUE_BAD_HOSTNAME, CURLUE_BAD_IPV6,
 *         CURLUE_BAD_PORT_NUMBER, CURLUE_OUT_OF_MEMORY, or any code from
 *         parse_hostname_login().
 * @note A missing host takes precedence over port number problems.
 * @warning The caller owns and must free @p host even on error.
 */
static CURLUcode parse_authority(struct Curl_URL *u,
                                 const char *auth, size_t authlen,
                                 unsigned int flags,
                                 struct dynbuf *host,
                                 bool has_scheme)
{
  size_t offset;
  CURLUcode uc;
  CURLcode result;

  /*
   * Parse the login details and strip them out of the hostname.
   */
  uc = parse_hostname_login(u, auth, authlen, flags, &offset);
  if(uc)
    return uc;

  result = curlx_dyn_addn(host, auth + offset, authlen - offset);
  if(result) {
    uc = cc2cu(result);
    return uc;
  }

  /* parse_port() also sets the hostname length correctly */
  uc = parse_port(u, host, has_scheme);

  if(!curlx_dyn_len(host))
    /* this makes no-host errors override port number problems */
    uc = CURLUE_NO_HOST;
  if(!uc)
    uc = urldecode_host(host);
  if(uc)
    ;
  else if(auth[offset] == '[')
    uc = ipv6_parse(u, curlx_dyn_ptr(host), curlx_dyn_len(host));
  else {
    /* ipv4_normalize() returns *NAME, *IPV4 or *ERROR */
    int type = ipv4_normalize(host);

    if(type == HOST_NAME)
      uc = Curl_hostname_check(curlx_dyn_ptr(host), curlx_dyn_len(host));
    else if(type == HOST_ERROR)
      uc = CURLUE_OUT_OF_MEMORY;
  }

  return uc;
}

/**
 * @brief Set the host (and port) of a handle from an authority string.
 *
 * Used for HTTP/2 server push, where the pushed request carries an
 * ":authority" value. User info is not allowed in the authority.
 *
 * @param[in,out] u         URL handle; its host is replaced on success.
 * @param[in]     authority NUL-terminated "host[:port]" string.
 * @return CURLUE_OK on success.
 * @return Otherwise the parse error, see parse_authority().
 * @post On success u->host owns the new hostname buffer.
 */
CURLUcode Curl_url_set_authority(CURLU *u, const char *authority)
{
  CURLUcode ures;
  struct dynbuf host;

  DEBUGASSERT(authority);
  curlx_dyn_init(&host, CURL_MAX_INPUT_LENGTH);

  ures = parse_authority(u, authority, strlen(authority),
                         CURLU_DISALLOW_USER, &host, !!u->scheme);
  if(ures)
    curlx_dyn_free(&host);
  else {
    curlx_free(u->host);
    u->host = curlx_dyn_ptr(&host);
  }
  return ures;
}

/**
 * @brief Test for a "." path segment character, also as "%2e".
 *
 * Part of the "Remove Dot Segments" algorithm
 * (https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4).
 * If a dot (or its percent-encoded form, case-insensitive) is at the
 * front, the string pointer and length are advanced past it.
 *
 * @param[in,out] str  Current position; advanced by 1 or 3 on a match.
 * @param[in,out] clen Remaining length; decreased accordingly.
 * @return TRUE if a dot was consumed, FALSE otherwise (nothing changed).
 */

static bool is_dot(const char **str, size_t *clen)
{
  const char *p = *str;
  if(*p == '.') {
    (*str)++;
    (*clen)--;
    return TRUE;
  }
  else if((*clen >= 3) &&
          (p[0] == '%') && (p[1] == '2') && ((p[2] | 0x20) == 'e')) {
    *str += 3;
    *clen -= 3;
    return TRUE;
  }
  return FALSE;
}

/**
 * @def ISSLASH
 * @brief Test whether a character is the path separator '/'.
 */
#define ISSLASH(x) ((x) == '/')

/**
 * @brief Prescan a path to see if dot segment removal is needed.
 * @internal
 *
 * @param[in] p  Path bytes.
 * @param[in] pn Length of the path.
 * @return TRUE if the path contains a "." or ".." segment (also in
 *         percent-encoded form), FALSE if it can be used unchanged.
 */
static bool needs_dedotdot(const char *p, size_t pn)
{
  /* a single byte path cannot be cleaned up */
  if(pn < 2)
    return FALSE;
  if(!memchr(p, '.', pn) && !memchr(p, '%', pn))
    return FALSE;
  while(pn) {
    if(is_dot(&p, &pn)) {
      /* "./" or dot before end of string */
      if(!pn || ISSLASH(*p))
        return TRUE;
      /* "../" or ".." before end of string */
      else if(is_dot(&p, &pn) && (!pn || ISSLASH(*p)))
        return TRUE;
    }
    else {
      p++;
      pn--;
    }
  }
  return FALSE;
}

/**
 * @brief Remove "." and ".." segments from a path (RFC 3986 5.2.4).
 *
 * Takes a path with dot and dotdot sequences and strips them according to
 * the rules in RFC 3986 section 5.2.4. The function handles a path only;
 * it must not contain the query or fragment.
 *
 * @param[in]  input Path bytes.
 * @param[in]  clen  Length of @p input in bytes.
 * @param[out] outp  Set to a newly allocated, NUL-terminated cleaned path,
 *                   or to NULL if the path needed no change.
 * @return 0 on success. 1 on out of memory.
 * @note Unit tested by unit test 1395.
 * @warning The caller owns the string returned in @p outp and must free it.
 */
UNITTEST int dedotdotify(const char *input, size_t clen, char **outp);
UNITTEST int dedotdotify(const char *input, size_t clen, char **outp)
{
  struct dynbuf out;
  CURLcode result = CURLE_OK;

  /* variables for leading dot checks */
  const char *dinput = input;
  size_t dlen = clen;

  *outp = NULL;
  if(!needs_dedotdot(input, clen))
    return 0;

  curlx_dyn_init(&out, clen + 1);

  /* if the input buffer begins with a prefix of "../" or "./", then remove
     that prefix from the input buffer; otherwise, */
  if(is_dot(&dinput, &dlen)) {
    if(ISSLASH(*dinput)) {
      /* one dot followed by a slash */
      input = dinput + 1;
      clen = dlen - 1;
    }

    /* if the input buffer consists only of "." or "..", then remove
       that from the input buffer; otherwise, */
    else if(is_dot(&dinput, &dlen)) {
      if(!dlen)
        /* .. [end] */
        goto end;
      else if(ISSLASH(*dinput)) {
        /* ../ */
        input = dinput + 1;
        clen = dlen - 1;
      }
    }
  }

  while(clen && !result) { /* until end of path content */
    const char *next;
    size_t seglen;
    if(ISSLASH(*input)) {
      const char *p = &input[1];
      size_t blen = clen - 1;
      /* if the input buffer begins with a prefix of "/./" or "/.", where "."
         is a complete path segment, then replace that prefix with "/" in the
         input buffer; otherwise, */
      if(is_dot(&p, &blen)) {
        if(!blen) { /* /. */
          result = curlx_dyn_addn(&out, "/", 1);
          break;
        }
        else if(ISSLASH(*p)) { /* /./ */
          input = p;
          clen = blen;
          continue;
        }

        /* if the input buffer begins with a prefix of "/../" or "/..", where
           ".." is a complete path segment, then replace that prefix with "/"
           in the input buffer and remove the last segment and its preceding
           "/" (if any) from the output buffer; otherwise, */
        else if(is_dot(&p, &blen) && (ISSLASH(*p) || !blen)) {
          /* remove the last segment from the output buffer */
          size_t len = curlx_dyn_len(&out);
          if(len) {
            const char *ptr = curlx_dyn_ptr(&out);
            const char *last = memrchr(ptr, '/', len);
            if(last)
              /* trim the output at the slash */
              curlx_dyn_setlen(&out, last - ptr);
          }

          if(blen) { /* /../ */
            input = p;
            clen = blen;
            continue;
          }
          result = curlx_dyn_addn(&out, "/", 1);
          break;
        }
      }
    }

    /* move the first path segment in the input buffer to the end of the
       output buffer, including the initial "/" character (if any) and any
       subsequent characters up to, but not including, the next "/" character
       or the end of the input buffer. */

    next = memchr(input + 1, '/', clen - 1);
    seglen = next ? (size_t)(next - input) : clen;
    result = curlx_dyn_addn(&out, input, seglen);
    input += seglen;
    clen -= seglen;
  }
end:
  if(!result) {
    if(curlx_dyn_len(&out))
      *outp = curlx_dyn_ptr(&out);
    else {
      *outp = curlx_strdup("");
      if(!*outp)
        return 1;
    }
  }
  return result ? 1 : 0; /* success */
}

/**
 * @brief Parse a "file:" URL and find its path.
 * @internal
 *
 * Validates the form per RFC 8089. An authority is accepted only if it is
 * empty, "localhost" or "127.0.0.1" (a Windows drive letter is also fine
 * on Windows). On non-Windows systems drive letters are refused. On success
 * the scheme is stored as "file".
 *
 * @param[in]     url      The complete NUL-terminated URL.
 * @param[in]     urllen   Length of @p url.
 * @param[in,out] u        URL handle; its scheme is set to "file".
 * @param[out]    pathp    Points into @p url at the start of the path.
 * @param[out]    pathlenp Length of the path including query and fragment.
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_FILE_URL for a too short URL, a path not starting
 *         with '/', a disallowed host or an unsupported drive letter.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @note @p pathp is not allocated; it only references @p url.
 * @note Unit tested by unit test 1675.
 */
UNITTEST CURLUcode parse_file(const char *url, size_t urllen, CURLU *u,
                              const char **pathp, size_t *pathlenp);
UNITTEST CURLUcode parse_file(const char *url, size_t urllen, CURLU *u,
                              const char **pathp, size_t *pathlenp)
{
  const char *path;
  size_t pathlen;

  *pathp = NULL;
  *pathlenp = 0;
  if(urllen <= 6)
    /* file:/ is not enough to actually be a complete file: URL */
    return CURLUE_BAD_FILE_URL;

  /* path has been allocated large enough to hold this */
  path = &url[5];
  pathlen = urllen - 5;

  /* RFC 8089: file-hier-part = ( "//" auth-path ) / local-path, where
     local-path also starts with a "/". So reject anything that does not
     start with at least one "/" */
  if(path[0] != '/')
    return CURLUE_BAD_FILE_URL;

  /* Extra handling URLs with an authority component (i.e. that start with
   * "file://")
   *
   * We allow omitted hostname (e.g. file:/<path>) -- valid according to
   * RFC 8089, but not the (current) WHAT-WG URL spec.
   */
  if(path[1] == '/') {
    /* swallow the two slashes */
    const char *ptr = &path[2];

    /*
     * According to RFC 8089, a file: URL can be reliably dereferenced if:
     *
     *  o it has no/blank hostname, or
     *
     *  o the hostname matches "localhost" (case-insensitively), or
     *
     *  o the hostname is a FQDN that resolves to this machine, or
     *
     * For brevity, we only consider URLs with empty, "localhost", or
     * "127.0.0.1" hostnames as local, otherwise as an UNC String.
     *
     * Additionally, there is an exception for URLs with a Windows drive
     * letter in the authority (which was accidentally omitted from RFC 8089
     * Appendix E, but believe me, it was meant to be there. --MK)
     */
    if(ptr[0] != '/' && !STARTS_WITH_URL_DRIVE_PREFIX(ptr)) {
      /* the URL includes a hostname, it must match "localhost" or
         "127.0.0.1" to be valid */
      if(checkprefix("localhost/", ptr) ||
         checkprefix("127.0.0.1/", ptr)) {
        ptr += 9; /* now points to the slash after the host */
      }
      else
        /* Invalid file://hostname/, expected localhost or 127.0.0.1 or
           none */
        return CURLUE_BAD_FILE_URL;
    }

    path = ptr;
    pathlen = urllen - (ptr - url);
  }

#if !defined(_WIN32) && !defined(MSDOS) && !defined(__CYGWIN__)
  /* Do not allow Windows drive letters when not in Windows.
   * This catches both "file:/c:" and "file:c:" */
  if(('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) ||
     STARTS_WITH_URL_DRIVE_PREFIX(path)) {
    /* File drive letters are only accepted in MS-DOS/Windows */
    return CURLUE_BAD_FILE_URL;
  }
#else
  /* If the path starts with a slash and a drive letter, ditch the slash */
  if('/' == path[0] && STARTS_WITH_URL_DRIVE_PREFIX(&path[1])) {
    /* This cannot be done with strcpy, as the memory chunks overlap! */
    path++;
    pathlen--;
  }
#endif
  u->scheme = curlx_strdup("file");
  if(!u->scheme)
    return CURLUE_OUT_OF_MEMORY;

  *pathp = path;
  *pathlenp = pathlen;
  return CURLUE_OK;
}

/**
 * @brief Validate the scheme and locate where the authority starts.
 * @internal
 *
 * For a URL with a scheme, checks it is supported (unless
 * CURLU_NON_SUPPORT_SCHEME), skips the slashes after the colon and stores
 * the scheme in the handle. Without a scheme it fails unless
 * CURLU_DEFAULT_SCHEME or CURLU_GUESS_SCHEME is set; the default scheme is
 * stored only for CURLU_DEFAULT_SCHEME.
 *
 * @param[in]     url       The complete URL.
 * @param[in,out] u         URL handle receiving the scheme.
 * @param[in]     schemebuf Lowercased scheme, as found by
 *                          Curl_is_absolute_url().
 * @param[in]     schemelen Length of the scheme, 0 if none was found.
 * @param[in]     flags     CURLU_* flags.
 * @param[out]    hostpp    Set to where the hostname starts in @p url.
 * @return CURLUE_OK on success.
 * @return CURLUE_UNSUPPORTED_SCHEME for an unknown scheme.
 * @return CURLUE_BAD_SLASHES for a bad number of slashes.
 * @return CURLUE_BAD_SCHEME if no scheme is present and none may be
 *         guessed or defaulted.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 */
static CURLUcode parse_scheme(const char *url, CURLU *u, char *schemebuf,
                              size_t schemelen, unsigned int flags,
                              const char **hostpp)
{
  /* clear path */
  const char *schemep = NULL;

  if(schemelen) {
    int num_slashes = 0;
    const char *p = &url[schemelen + 1];
    if(!Curl_getn_scheme(schemebuf, schemelen) &&
       !(flags & CURLU_NON_SUPPORT_SCHEME))
      return CURLUE_UNSUPPORTED_SCHEME;

    if(!ISSLASH(*p))
      /* less than one */
      return CURLUE_BAD_SLASHES;
    if((flags & CURLU_NO_AUTHORITY)) {
      while(ISSLASH(*p) && (num_slashes < 2)) {
        p++;
        num_slashes++;
      }
    }
    else {
      while(ISSLASH(*p) && (num_slashes < 4)) {
        p++;
        num_slashes++;
      }
      if(num_slashes > 3)
        return CURLUE_BAD_SLASHES;
    }

    schemep = schemebuf;
    *hostpp = p; /* hostname starts here */
  }
  else {
    /* no scheme! */

    if(!(flags & (CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME)))
      return CURLUE_BAD_SCHEME;

    if(flags & CURLU_DEFAULT_SCHEME)
      schemep = DEFAULT_SCHEME;

    /*
     * The URL was badly formatted, let's try without scheme specified.
     */
    *hostpp = url;
  }

  if(schemep) {
    u->scheme = curlx_strdup(schemep);
    if(!u->scheme)
      return CURLUE_OUT_OF_MEMORY;
  }
  return CURLUE_OK;
}

/**
 * @brief Guess the scheme from the start of the hostname.
 * @internal
 *
 * Legacy curl behavior: "ftp.", "dict.", "ldap.", "imap.", "smtp." and
 * "pop3." prefixes select that protocol, anything else gets "http". The
 * handle is marked as having a guessed scheme.
 *
 * @param[in,out] u    URL handle; scheme and guessed_scheme are set.
 * @param[in]     host Host buffer inspected.
 * @return CURLUE_OK on success.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 */
static CURLUcode guess_scheme(CURLU *u, struct dynbuf *host)
{
  const char *hostname = curlx_dyn_ptr(host);
  const char *schemep = NULL;
  /* legacy curl-style guess based on hostname */
  if(checkprefix("ftp.", hostname))
    schemep = "ftp";
  else if(checkprefix("dict.", hostname))
    schemep = "dict";
  else if(checkprefix("ldap.", hostname))
    schemep = "ldap";
  else if(checkprefix("imap.", hostname))
    schemep = "imap";
  else if(checkprefix("smtp.", hostname))
    schemep = "smtp";
  else if(checkprefix("pop3.", hostname))
    schemep = "pop3";
  else
    schemep = "http";

  u->scheme = curlx_strdup(schemep);
  if(!u->scheme)
    return CURLUE_OUT_OF_MEMORY;

  u->guessed_scheme = TRUE;
  return CURLUE_OK;
}

/**
 * @brief Store the fragment of a URL being parsed.
 * @internal
 *
 * @param[in,out] u        URL handle receiving the fragment.
 * @param[in]     fragment Points at the leading '#'.
 * @param[in]     fraglen  Length including the '#'.
 * @param[in]     flags    CURLU_* flags (CURLU_URLENCODE, CURLU_ALLOW_SPACE).
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_FRAGMENT on forbidden bytes.
 * @return CURLUE_OUT_OF_MEMORY or the encoder error otherwise.
 * @post u->fragment_present is TRUE; u->fragment stays NULL for an empty
 *       fragment ("#" alone).
 */
static CURLUcode handle_fragment(CURLU *u, const char *fragment,
                                 size_t fraglen, unsigned int flags)
{
  CURLUcode ures;
  u->fragment_present = TRUE;
  if(fraglen > 1) {
    /* skip the leading '#' in the copy but include the null-terminator */
    if(flags & CURLU_URLENCODE) {
      struct dynbuf enc;
      curlx_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
      ures = urlencode_str(&enc, fragment + 1, fraglen - 1, TRUE, QUERY_NO);
      if(ures)
        return ures;
      u->fragment = curlx_dyn_ptr(&enc);
    }
    else {
      if(badoctets(fragment, fraglen, flags))
        return CURLUE_BAD_FRAGMENT;
      u->fragment = curlx_memdup0(fragment + 1, fraglen - 1);
      if(!u->fragment)
        return CURLUE_OUT_OF_MEMORY;
    }
  }
  return CURLUE_OK;
}

/**
 * @brief Store the query of a URL being parsed.
 * @internal
 *
 * @param[in,out] u     URL handle receiving the query.
 * @param[in]     query Points at the leading '?'.
 * @param[in]     qlen  Length including the '?'.
 * @param[in]     flags CURLU_* flags (CURLU_URLENCODE, CURLU_ALLOW_SPACE).
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_QUERY on forbidden bytes.
 * @return CURLUE_OUT_OF_MEMORY or the encoder error otherwise.
 * @post u->query_present is TRUE; a lone '?' stores an empty string.
 */
static CURLUcode handle_query(CURLU *u, const char *query,
                              size_t qlen, unsigned int flags)
{
  u->query_present = TRUE;
  if(qlen > 1) {
    if(flags & CURLU_URLENCODE) {
      struct dynbuf enc;
      CURLUcode ures;
      curlx_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
      /* skip the leading question mark */
      ures = urlencode_str(&enc, query + 1, qlen - 1, TRUE, QUERY_YES);
      if(ures)
        return ures;
      u->query = curlx_dyn_ptr(&enc);
    }
    else {
      if(badoctets(query, qlen, flags))
        return CURLUE_BAD_QUERY;

      u->query = curlx_memdup0(query + 1, qlen - 1);
      if(!u->query)
        return CURLUE_OUT_OF_MEMORY;
    }
  }
  else {
    /* single byte query */
    u->query = curlx_strdup("");
    if(!u->query)
      return CURLUE_OUT_OF_MEMORY;
  }
  return CURLUE_OK;
}

/**
 * @brief Store the path of a URL being parsed.
 * @internal
 *
 * Optionally URL-encodes it, checks for forbidden bytes and removes dot
 * segments unless CURLU_PATH_AS_IS is set.
 *
 * @param[in,out] u       URL handle receiving the path.
 * @param[in]     path    Path bytes (query and fragment already removed).
 * @param[in]     pathlen Length of @p path.
 * @param[in]     flags   CURLU_* flags.
 * @param[in]     is_file TRUE for file: URLs, where a one byte path ("/")
 *                        is stored; other schemes need at least two bytes,
 *                        a lone "/" is the same as no path.
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_PATH on forbidden bytes.
 * @return CURLUE_OUT_OF_MEMORY or the encoder error otherwise.
 */
static CURLUcode handle_path(CURLU *u, const char *path,
                             size_t pathlen, unsigned int flags,
                             bool is_file)
{
  CURLUcode ures;
  if(pathlen && (flags & CURLU_URLENCODE)) {
    struct dynbuf enc;
    curlx_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
    ures = urlencode_str(&enc, path, pathlen, TRUE, QUERY_NO);
    if(ures)
      return ures;
    pathlen = curlx_dyn_len(&enc);
    path = u->path = curlx_dyn_ptr(&enc);
  }

  if(pathlen >= (size_t)(1 + !is_file)) {
    if(badoctets(path, pathlen, flags))
      return CURLUE_BAD_PATH;

    /* paths for file:// scheme can be one byte, others need to be two */
    if(!u->path) {
      u->path = curlx_memdup0(path, pathlen);
      if(!u->path)
        return CURLUE_OUT_OF_MEMORY;
      path = u->path;
    }
    else if(flags & CURLU_URLENCODE)
      /* it might have encoded more than the path so cut it */
      u->path[pathlen] = 0;

    if(!(flags & CURLU_PATH_AS_IS)) {
      /* remove ../ and ./ sequences according to RFC3986 */
      char *dedot;
      int err = dedotdotify(path, pathlen, &dedot);
      if(err)
        return CURLUE_OUT_OF_MEMORY;
      if(dedot) {
        curlx_free(u->path);
        u->path = dedot;
      }
    }
  }
  return CURLUE_OK;
}

/**
 * @brief Parse a complete URL string into a handle.
 * @internal
 *
 * Splits the URL into scheme, authority, path, query and fragment and
 * stores the pieces in @p u. Handles file: URLs separately.
 *
 * @param[in]     url   NUL-terminated URL, at most CURL_MAX_INPUT_LENGTH.
 * @param[in,out] u     URL handle to fill; expected to be empty.
 * @param[in]     flags CURLU_* flags.
 * @return CURLUE_OK on success.
 * @return CURLUE_MALFORMED_INPUT if the URL is too long.
 * @return Any error of the sub parsers (CURLUE_NO_HOST,
 *         CURLUE_BAD_SCHEME, CURLUE_BAD_HOSTNAME, ...).
 * @post On failure @p u is cleared of all allocated members.
 */
static CURLUcode parseurl(const char *url, CURLU *u, unsigned int flags)
{
  const char *path;
  size_t pathlen;
  char schemebuf[MAX_SCHEME_LEN + 1];
  size_t schemelen = 0;
  size_t urllen;
  CURLUcode ures = CURLUE_OK;
  struct dynbuf host;
  bool is_file = FALSE;

  DEBUGASSERT(url);

  urllen = strlen(url);
  if(urllen > CURL_MAX_INPUT_LENGTH)
    return CURLUE_MALFORMED_INPUT;

  curlx_dyn_init(&host, CURL_MAX_INPUT_LENGTH);

  schemelen = Curl_is_absolute_url(url, schemebuf, sizeof(schemebuf),
                                   flags & (CURLU_GUESS_SCHEME |
                                            CURLU_DEFAULT_SCHEME));

  /* handle the file: scheme */
  if(schemelen == 4 && !memcmp(schemebuf, "file", 4)) {
    is_file = TRUE;
    ures = parse_file(url, urllen, u, &path, &pathlen);
  }
  else {
    const char *hostp = NULL;
    const char *p;
    size_t hostlen;
    ures = parse_scheme(url, u, schemebuf, schemelen, flags, &hostp);
    if(ures)
      goto fail;

    /* find the end of the hostname + port number */
    p = hostp;
    while(*p && *p != '/' && *p != '?' && *p != '#')
      p++;
    hostlen = p - hostp;
    path = p;

    /* this pathlen also contains the query and the fragment */
    pathlen = urllen - (path - url);
    if(hostlen) {
      ures = parse_authority(u, hostp, hostlen, flags, &host, !!u->scheme);
      if(!ures && (flags & CURLU_GUESS_SCHEME) && !u->scheme)
        ures = guess_scheme(u, &host);
    }
    else if(flags & CURLU_NO_AUTHORITY) {
      /* allowed to be empty. */
      if(curlx_dyn_add(&host, ""))
        ures = CURLUE_OUT_OF_MEMORY;
    }
    else
      ures = CURLUE_NO_HOST;
  }
  if(!ures) {
    /* The path might at this point contain a fragment and/or a query to
       handle */
    const char *fragment = memchr(path, '#', pathlen);
    if(fragment) {
      size_t fraglen = pathlen - (fragment - path);
      ures = handle_fragment(u, fragment, fraglen, flags);
      /* after this, pathlen still contains the query */
      pathlen -= fraglen;
    }
  }
  if(!ures) {
    const char *query = memchr(path, '?', pathlen);
    if(query) {
      size_t qlen = pathlen - (query - path);
      ures = handle_query(u, query, qlen, flags);
      pathlen -= qlen;
    }
  }
  if(!ures)
    /* the fragment and query parts are trimmed off from the path */
    ures = handle_path(u, path, pathlen, flags, is_file);
  if(!ures) {
    u->host = curlx_dyn_ptr(&host);
    return CURLUE_OK;
  }
fail:
  curlx_dyn_free(&host);
  free_urlhandle(u);
  return ures;
}

/**
 * @brief Parse a URL and, if successful, replace the handle content.
 * @internal
 *
 * The URL is parsed into a temporary handle so the existing content is
 * kept intact if parsing fails.
 *
 * @param[in]     url   NUL-terminated URL to parse.
 * @param[in,out] u     URL handle; replaced entirely on success.
 * @param[in]     flags CURLU_* flags.
 * @return CURLUE_OK on success, otherwise the error from parseurl().
 * @post On failure @p u is unchanged.
 */
static CURLUcode parseurl_and_replace(const char *url, CURLU *u,
                                      unsigned int flags)
{
  CURLUcode ures;
  CURLU tmpurl;
  memset(&tmpurl, 0, sizeof(tmpurl));
  ures = parseurl(url, &tmpurl, flags);
  if(!ures) {
    free_urlhandle(u);
    *u = tmpurl;
  }
  return ures;
}

/**
 * @brief Resolve a relative URL against a base URL.
 * @internal
 *
 * Concatenates the relative reference onto the base, making it absolute,
 * and parses the result into @p u. Supports protocol-relative ("//host"),
 * absolute-path ("/path"), fragment-only ("#frag"), query-only ("?q")
 * and relative-path references.
 *
 * @param[in]     base   Complete, NUL-terminated base URL.
 * @param[in]     relurl The relative reference.
 * @param[in,out] u      URL handle receiving the result.
 * @param[in]     flags  CURLU_* flags (CURLU_PATH_AS_IS is dropped as the
 *                       base is merged then normalized).
 * @return CURLUE_OK on success.
 * @return CURLUE_MALFORMED_INPUT if @p base is NULL.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure or the parse error.
 */
static CURLUcode redirect_url(const char *base, const char *relurl,
                              CURLU *u, unsigned int flags)
{
  struct dynbuf urlbuf;
  bool host_changed = FALSE;
  const char *useurl = relurl;
  const char *cutoff = NULL;
  size_t prelen;
  CURLUcode uc;
  /* this can get here with a NULL u->scheme only if asked to use the default
     scheme, so allow fallback to that */
  const char *scheme = u->scheme ? u->scheme : DEFAULT_SCHEME;

  /* protsep points to the start of the hostname, after [scheme]:// */
  const char *protsep = base + strlen(scheme) + 3;
  DEBUGASSERT(base && relurl && u); /* all set here */
  if(!base)
    return CURLUE_MALFORMED_INPUT; /* should never happen */

  /* handle different relative URL types */
  switch(relurl[0]) {
  case '/':
    if(relurl[1] == '/') {
      /* protocol-relative URL: //example.com/path */
      cutoff = protsep;
      useurl = &relurl[2];
      host_changed = TRUE;
    }
    else
      /* absolute /path */
      cutoff = strchr(protsep, '/');
    break;

  case '#':
    /* fragment-only change */
    if(u->fragment_present)
      cutoff = strchr(protsep, '#');
    break;

  default:
    /* path or query-only change */
    if(u->query_present)
      /* remove existing query */
      cutoff = strchr(protsep, '?');
    else if(u->fragment_present)
      /* Remove existing fragment */
      cutoff = strchr(protsep, '#');

    if(relurl[0] != '?') {
      /* append a relative path after the last slash */
      cutoff = memrchr(protsep, '/',
                       cutoff ? (size_t)(cutoff - protsep) : strlen(protsep));
      if(cutoff)
        cutoff++; /* truncate after last slash */
    }
    break;
  }

  prelen = cutoff ? (size_t)(cutoff - base) : strlen(base);

  /* build new URL */
  curlx_dyn_init(&urlbuf, CURL_MAX_INPUT_LENGTH);

  if(!curlx_dyn_addn(&urlbuf, base, prelen) &&
     !urlencode_str(&urlbuf, useurl, strlen(useurl), !host_changed,
                    QUERY_NOT_YET)) {
    uc = parseurl_and_replace(curlx_dyn_ptr(&urlbuf), u,
                              flags & ~U_CURLU_PATH_AS_IS);
  }
  else
    uc = CURLUE_OUT_OF_MEMORY;

  curlx_dyn_free(&urlbuf);
  return uc;
}

/**
 * @brief Create a new, empty URL handle.
 * @ingroup urlapi
 *
 * @return A new CURLU handle, or NULL on out of memory.
 * @warning Release with curl_url_cleanup(); the handle is not
 *          thread-safe.
 * @see curl_url_cleanup(), curl_url_dup()
 */
CURLU *curl_url(void)
{
  return curlx_calloc(1, sizeof(struct Curl_URL));
}

/**
 * @brief Free a URL handle and all of its content.
 * @ingroup urlapi
 *
 * @param[in] u Handle to free. NULL is allowed and does nothing.
 * @post The handle and the strings it owns are invalid.
 * @see curl_url()
 */
void curl_url_cleanup(CURLU *u)
{
  if(u) {
    free_urlhandle(u);
    curlx_free(u);
  }
}

/**
 * @def DUP
 * @brief Duplicate one string member from @p src to @p dest.
 *
 * @param dest Destination CURLU pointer.
 * @param src  Source CURLU pointer.
 * @param name Member name to copy.
 * @warning Jumps to the label "fail" on allocation failure; the using
 *          function must define it.
 */
#define DUP(dest, src, name)                    \
  do {                                          \
    if((src)->name) {                           \
      (dest)->name = curlx_strdup((src)->name); \
      if(!(dest)->name)                         \
        goto fail;                              \
    }                                           \
  } while(0)

/**
 * @brief Make a deep copy of a URL handle.
 * @ingroup urlapi
 *
 * @param[in] in Handle to duplicate; may be NULL.
 * @return A new independent handle, or NULL if @p in is NULL or memory
 *         ran out.
 * @post The caller owns the copy and must call curl_url_cleanup().
 */
CURLU *curl_url_dup(const CURLU *in)
{
  struct Curl_URL *u;

  if(!in)
    return NULL;

  u = curlx_calloc(1, sizeof(struct Curl_URL));
  if(u) {
    DUP(u, in, scheme);
    DUP(u, in, user);
    DUP(u, in, password);
    DUP(u, in, options);
    DUP(u, in, host);
    DUP(u, in, path);
    DUP(u, in, query);
    DUP(u, in, fragment);
    DUP(u, in, zoneid);
    u->portnum = in->portnum;
    u->port_present = in->port_present;
    u->fragment_present = in->fragment_present;
    u->query_present = in->query_present;
    u->guessed_scheme = in->guessed_scheme;
  }
  return u;
fail:
  curl_url_cleanup(u);
  return NULL;
}

/**
 * @def host_decode
 * @def host_encode
 * @brief Convert a hostname to/from IDN, or report CURLUE_LACKS_IDN.
 *
 * Without IDN support both resolve to CURLUE_LACKS_IDN.
 */
#ifndef USE_IDN
#define host_decode(x, y) CURLUE_LACKS_IDN
#define host_encode(x, y) CURLUE_LACKS_IDN
#else
/**
 * @brief Convert a punycode hostname into its IDN (UTF-8) form.
 * @internal
 *
 * @param[in]  host      ASCII (punycode) hostname.
 * @param[out] allochost Newly allocated converted name on success.
 * @return CURLUE_OK on success.
 * @return CURLUE_OUT_OF_MEMORY on out of memory.
 * @return CURLUE_BAD_HOSTNAME if the conversion fails.
 * @warning The caller must free @p allochost.
 */
static CURLUcode host_decode(const char *host, char **allochost)
{
  CURLcode result = Curl_idn_decode(host, allochost);
  if(result)
    return (result == CURLE_OUT_OF_MEMORY) ?
      CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
  return CURLUE_OK;
}

/**
 * @brief Convert an IDN (UTF-8) hostname into its punycode form.
 * @internal
 *
 * @param[in]  host      Non-ASCII hostname.
 * @param[out] allochost Newly allocated converted name on success.
 * @return CURLUE_OK on success.
 * @return CURLUE_OUT_OF_MEMORY on out of memory.
 * @return CURLUE_BAD_HOSTNAME if the conversion fails.
 * @warning The caller must free @p allochost.
 */
static CURLUcode host_encode(const char *host, char **allochost)
{
  CURLcode result = Curl_idn_encode(host, allochost);
  if(result)
    return (result == CURLE_OUT_OF_MEMORY) ?
      CURLUE_OUT_OF_MEMORY : CURLUE_BAD_HOSTNAME;
  return CURLUE_OK;
}
#endif

/**
 * @brief Produce an output copy of a URL part, applying get-flags.
 * @internal
 *
 * Duplicates @p ptr and applies the transformations requested by the flags:
 * '+' to space for queries, URL decode, URL encode, or punycode/IDN
 * conversion of the host.
 *
 * @param[in]  u          URL handle (the host is used for the IDN test).
 * @param[in]  what       The part being fetched.
 * @param[in]  ptr        The stored part content.
 * @param[out] partp      Receives a newly allocated string (NULL on error).
 * @param[in]  plusdecode TRUE to convert '+' to ' ' (query decode).
 * @param[in]  flags      CURLU_URLDECODE, CURLU_URLENCODE,
 *                        CURLU_PUNYCODE and CURLU_PUNY2IDN are used.
 * @return CURLUE_OK on success.
 * @return CURLUE_URLDECODE if decoding fails or yields control bytes.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @return CURLUE_LACKS_IDN or CURLUE_BAD_HOSTNAME for IDN problems.
 * @warning The caller owns the string stored in @p partp.
 */
static CURLUcode urlget_format(const CURLU *u, CURLUPart what,
                               const char *ptr, char **partp,
                               bool plusdecode, unsigned int flags)
{
  CURLUcode uc = CURLUE_OK;
  size_t partlen = strlen(ptr);
  bool urldecode = (flags & CURLU_URLDECODE) ? 1 : 0;
  bool urlencode = (flags & CURLU_URLENCODE) ? 1 : 0;
  bool punycode = (flags & CURLU_PUNYCODE) && (what == CURLUPART_HOST);
  bool depunyfy = (flags & CURLU_PUNY2IDN) && (what == CURLUPART_HOST);
  char *part = curlx_memdup0(ptr, partlen);
  *partp = NULL;
  if(!part)
    return CURLUE_OUT_OF_MEMORY;
  if(plusdecode) {
    /* convert + to space */
    char *plus = part;
    size_t i = 0;
    for(i = 0; i < partlen; ++plus, i++) {
      if(*plus == '+')
        *plus = ' ';
    }
  }
  if(urldecode) {
    char *decoded;
    size_t dlen;
    /* this unconditional rejection of control bytes is documented API
       behavior */
    CURLcode result = Curl_urldecode(part, partlen, &decoded, &dlen,
                                     REJECT_CTRL);
    curlx_free(part);
    if(result)
      return CURLUE_URLDECODE;
    part = decoded;
    partlen = dlen;
  }
  if(urlencode && partlen) {
    struct dynbuf enc;
    curlx_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
    uc = urlencode_str(&enc, part, partlen, TRUE, what == CURLUPART_QUERY ?
                       QUERY_YES : QUERY_NO);
    curlx_free(part);
    if(uc)
      return uc;
    part = curlx_dyn_ptr(&enc);
  }
  else if(punycode) {
    if(!Curl_is_ASCII_name(u->host)) {
      char *punyversion = NULL;
      uc = host_decode(part, &punyversion);
      curlx_free(part);
      if(uc)
        return uc;
      uc = Curl_hostname_check(punyversion, strlen(punyversion));
      if(uc) {
        curlx_free(punyversion);
        return uc;
      }
      part = punyversion;
    }
  }
  else if(depunyfy && Curl_is_ASCII_name(u->host)) {
    char *unpunified = NULL;
    uc = host_encode(part, &unpunified);
    curlx_free(part);
    if(uc)
      return uc;
    part = unpunified;
  }
  *partp = part;
  return CURLUE_OK;
}

/**
 * @brief Build a "file://" URL string from the handle.
 * @internal
 *
 * @param[in]  u           URL handle.
 * @param[out] part        Receives the allocated URL.
 * @param[in]  fragmentsep "#" or "" separator before the fragment.
 * @param[in]  querysep    "?" or "" separator before the query.
 * @return CURLUE_OK, or CURLUE_OUT_OF_MEMORY.
 * @warning The caller must free the string stored in @p part.
 */
static CURLUcode file_url(const CURLU *u, char **part,
                          const char *fragmentsep,
                          const char *querysep)
{
  char *url = curl_maprintf("file://%s%s%s%s%s",
                            u->path ? u->path : "/",
                            querysep, u->query ? u->query : "",
                            fragmentsep, u->fragment ? u->fragment : "");
  if(!url)
    return CURLUE_OUT_OF_MEMORY;

  *part = url;
  return CURLUE_OK;
}

/**
 * @brief Assemble the complete URL string from the stored parts.
 * @internal
 *
 * Applies CURLU_DEFAULT_SCHEME, CURLU_DEFAULT_PORT, CURLU_NO_DEFAULT_PORT,
 * CURLU_NO_GUESS_SCHEME, CURLU_GET_EMPTY, CURLU_URLENCODE, CURLU_PUNYCODE
 * and CURLU_PUNY2IDN. An IPv6 zone id is written as "%25zone".
 *
 * @param[in]  u     URL handle.
 * @param[out] part  Receives the allocated URL.
 * @param[in]  flags CURLU_* flags.
 * @return CURLUE_OK on success.
 * @return CURLUE_NO_HOST if there is no host (and not a file: URL).
 * @return CURLUE_NO_SCHEME if there is no scheme and no default allowed.
 * @return CURLUE_OUT_OF_MEMORY or an IDN/host error otherwise.
 * @warning The caller must free the string stored in @p part.
 */
static CURLUcode urlget_url(const CURLU *u, char **part, unsigned int flags)
{
  char *url;
  char *allochost = NULL;
  const char *fragmentsep =
    (u->fragment || (u->fragment_present && flags & CURLU_GET_EMPTY)) ?
    "#" : "";
  const char *querysep = ((u->query && u->query[0]) ||
                          (u->query_present && flags & CURLU_GET_EMPTY)) ?
    "?" : "";
  char portbuf[7];
  if(curl_strequal("file", u->scheme))
    return file_url(u, part, fragmentsep, querysep);
  else if(!u->host)
    return CURLUE_NO_HOST;
  else {
    const char *scheme;
    char *options = u->options;
    char *port = NULL;
    const struct Curl_scheme *h = NULL;
    char schemebuf[MAX_SCHEME_LEN + 5];
    if(u->scheme)
      scheme = u->scheme;
    else if(flags & CURLU_DEFAULT_SCHEME)
      scheme = DEFAULT_SCHEME;
    else
      return CURLUE_NO_SCHEME;

    if(u->port_present) {
      curl_msnprintf(portbuf, sizeof(portbuf), "%u", u->portnum);
      port = portbuf;
    }

    h = Curl_get_scheme(scheme);
    if(h) {
      if(!u->port_present && (flags & CURLU_DEFAULT_PORT)) {
        /* there is no stored port number, but asked to deliver a default one
           for the scheme */
        curl_msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
        port = portbuf;
      }
      else if(u->port_present && (h->defport == u->portnum) &&
              (flags & CURLU_NO_DEFAULT_PORT)) {
        /* there is a stored port number, but asked to inhibit if it matches
           the default port for the scheme */
        port = NULL;
      }

      if(!(h->flags & PROTOPT_URLOPTIONS))
        options = NULL;
    }

    if(u->host[0] == '[') {
      if(u->zoneid) {
        /* make it '[ host %25 zoneid ]' */
        struct dynbuf enc;
        size_t hostlen = strlen(u->host);
        curlx_dyn_init(&enc, CURL_MAX_INPUT_LENGTH);
        if(curlx_dyn_addf(&enc, "%.*s%%25%s]", (int)hostlen - 1, u->host,
                          u->zoneid))
          return CURLUE_OUT_OF_MEMORY;
        allochost = curlx_dyn_ptr(&enc);
      }
    }
    else if(flags & CURLU_URLENCODE) {
      allochost = curl_easy_escape(NULL, u->host, 0);
      if(!allochost)
        return CURLUE_OUT_OF_MEMORY;
    }
    else if(flags & CURLU_PUNYCODE) {
      if(!Curl_is_ASCII_name(u->host)) {
        CURLUcode ret = host_decode(u->host, &allochost);
        if(!ret)
          ret = Curl_hostname_check(allochost, strlen(allochost));
        if(ret) {
          curlx_safefree(allochost);
          return ret;
        }
      }
    }
    else if(flags & CURLU_PUNY2IDN) {
      if(Curl_is_ASCII_name(u->host)) {
        CURLUcode ret = host_encode(u->host, &allochost);
        if(ret)
          return ret;
      }
    }

    if(!(flags & CURLU_NO_GUESS_SCHEME) || !u->guessed_scheme)
      curl_msnprintf(schemebuf, sizeof(schemebuf), "%s://", scheme);
    else
      schemebuf[0] = 0;

    url = curl_maprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                        schemebuf,
                        u->user ? u->user : "",
                        u->password ? ":" : "",
                        u->password ? u->password : "",
                        options ? ";" : "",
                        options ? options : "",
                        (u->user || u->password || options) ? "@" : "",
                        allochost ? allochost : u->host,
                        port ? ":" : "",
                        port ? port : "",
                        u->path ? u->path : "/",
                        querysep,
                        u->query ? u->query : "",
                        fragmentsep,
                        u->fragment ? u->fragment : "");
    curlx_free(allochost);
  }
  if(!url)
    return CURLUE_OUT_OF_MEMORY;
  *part = url;
  return CURLUE_OK;
}

/**
 * @brief Extract a part of the URL in a handle.
 * @ingroup urlapi
 *
 * Returns a newly allocated copy of the requested component. The meaning
 * of @p flags is documented in the public libcurl-url man page.
 *
 * @param[in]  u     URL handle.
 * @param[in]  what  The part to extract (CURLUPART_*).
 * @param[out] part  Receives an allocated string on success, NULL
 *                   otherwise.
 * @param[in]  flags CURLU_* flags (CURLU_DEFAULT_PORT,
 *                   CURLU_NO_DEFAULT_PORT, CURLU_DEFAULT_SCHEME,
 *                   CURLU_NO_GUESS_SCHEME, CURLU_GET_EMPTY,
 *                   CURLU_URLDECODE, CURLU_URLENCODE, CURLU_PUNYCODE,
 *                   CURLU_PUNY2IDN).
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_HANDLE if @p u is NULL.
 * @return CURLUE_BAD_PARTPOINTER if @p part is NULL.
 * @return CURLUE_UNKNOWN_PART for an unknown @p what.
 * @return CURLUE_NO_SCHEME, CURLUE_NO_USER, CURLUE_NO_PASSWORD,
 *         CURLUE_NO_OPTIONS, CURLUE_NO_HOST, CURLUE_NO_ZONEID,
 *         CURLUE_NO_PORT, CURLUE_NO_QUERY or CURLUE_NO_FRAGMENT when the
 *         requested part is not present.
 * @return CURLUE_OUT_OF_MEMORY or a conversion error otherwise.
 * @warning The returned string must be released with curl_free().
 * @see curl_url_set()
 */
CURLUcode curl_url_get(const CURLU *u, CURLUPart what,
                       char **part, unsigned int flags)
{
  const char *ptr;
  CURLUcode ifmissing = CURLUE_UNKNOWN_PART;
  char portbuf[7];
  bool plusdecode = FALSE;
  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part)
    return CURLUE_BAD_PARTPOINTER;
  *part = NULL;

  /* Select the stored member for the requested part and what to report
     if it is not present. */
  switch(what) {
  case CURLUPART_SCHEME:
    ptr = u->scheme;
    ifmissing = CURLUE_NO_SCHEME;
    flags &= ~U_CURLU_URLDECODE; /* never for schemes */
    if((flags & CURLU_NO_GUESS_SCHEME) && u->guessed_scheme)
      return CURLUE_NO_SCHEME;
    break;
  case CURLUPART_USER:
    ptr = u->user;
    ifmissing = CURLUE_NO_USER;
    break;
  case CURLUPART_PASSWORD:
    ptr = u->password;
    ifmissing = CURLUE_NO_PASSWORD;
    break;
  case CURLUPART_OPTIONS:
    ptr = u->options;
    ifmissing = CURLUE_NO_OPTIONS;
    break;
  case CURLUPART_HOST:
    ptr = u->host;
    ifmissing = CURLUE_NO_HOST;
    break;
  case CURLUPART_ZONEID:
    ptr = u->zoneid;
    ifmissing = CURLUE_NO_ZONEID;
    break;
  case CURLUPART_PORT:
    ptr = NULL;
    ifmissing = CURLUE_NO_PORT;
    flags &= ~U_CURLU_URLDECODE; /* never for port */
    if(u->port_present) {
      const struct Curl_scheme *h = u->scheme ?
                                    Curl_get_scheme(u->scheme) : NULL;
      /* there is a stored port number, but ask to inhibit if
         it matches the default one for the scheme */
      if(h && (h->defport == u->portnum) &&
         (flags & CURLU_NO_DEFAULT_PORT)) {
        ptr = NULL;
      }
      else {
        curl_msnprintf(portbuf, sizeof(portbuf), "%u", u->portnum);
        ptr = portbuf;
      }
    }
    else if((flags & CURLU_DEFAULT_PORT) && u->scheme) {
      /* there is no stored port number, but asked to deliver
         a default one for the scheme */
      const struct Curl_scheme *h = Curl_get_scheme(u->scheme);
      if(h) {
        curl_msnprintf(portbuf, sizeof(portbuf), "%u", h->defport);
        ptr = portbuf;
      }
    }
    break;
  case CURLUPART_PATH:
    ptr = u->path;
    if(!ptr)
      ptr = "/";
    break;
  case CURLUPART_QUERY:
    ptr = u->query;
    ifmissing = CURLUE_NO_QUERY;
    plusdecode = flags & CURLU_URLDECODE;
    if(ptr && !ptr[0] && !(flags & CURLU_GET_EMPTY))
      /* there was a blank query and the user does not ask for it */
      ptr = NULL;
    break;
  case CURLUPART_FRAGMENT:
    ptr = u->fragment;
    ifmissing = CURLUE_NO_FRAGMENT;
    if(!ptr && u->fragment_present && flags & CURLU_GET_EMPTY)
      /* there was a blank fragment and the user asks for it */
      ptr = "";
    break;
  case CURLUPART_URL:
    return urlget_url(u, part, flags);
  default:
    ptr = NULL;
    break;
  }
  if(ptr)
    return urlget_format(u, what, ptr, part, plusdecode, flags);

  return ifmissing;
}

/**
 * @brief Validate a scheme string supplied to curl_url_set().
 * @internal
 *
 * @param[in,out] u      URL handle; guessed_scheme is cleared on success.
 * @param[in]     scheme The new scheme.
 * @param[in]     flags  CURLU_NON_SUPPORT_SCHEME allows schemes without a
 *                       protocol handler.
 * @return CURLUE_OK if acceptable.
 * @return CURLUE_BAD_SCHEME if empty, too long or has illegal characters.
 * @return CURLUE_UNSUPPORTED_SCHEME for an unknown scheme unless allowed.
 */
static CURLUcode set_url_scheme(CURLU *u, const char *scheme,
                                unsigned int flags)
{
  size_t plen = strlen(scheme);
  const struct Curl_scheme *h = NULL;
  if((plen > MAX_SCHEME_LEN) || (plen < 1))
    /* too long or too short */
    return CURLUE_BAD_SCHEME;
  /* verify that it is a fine scheme */
  h = Curl_get_scheme(scheme);
  if(!(flags & CURLU_NON_SUPPORT_SCHEME) && (!h || !h->run))
    return CURLUE_UNSUPPORTED_SCHEME;
  if(!h) {
    const char *s = scheme;
    if(ISALPHA(*s)) {
      /* ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
      s++;
      while(--plen) {
        if(ISALNUM(*s) || (*s == '+') || (*s == '-') || (*s == '.'))
          s++; /* fine */
        else
          return CURLUE_BAD_SCHEME;
      }
    }
    else
      return CURLUE_BAD_SCHEME;
  }
  u->guessed_scheme = FALSE;
  return CURLUE_OK;
}

/**
 * @brief Parse and store a port number given as a string.
 * @internal
 *
 * @param[in,out] u             URL handle receiving the port.
 * @param[in]     provided_port Decimal digits only, at most 65535.
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_PORT_NUMBER if not a plain decimal number in range.
 */
static CURLUcode set_url_port(CURLU *u, const char *provided_port)
{
  curl_off_t port;
  if(!ISDIGIT(provided_port[0]))
    /* not a number */
    return CURLUE_BAD_PORT_NUMBER;
  if(curlx_str_number(&provided_port, &port, 0xffff) || *provided_port)
    /* weirdly provided number, not good! */
    return CURLUE_BAD_PORT_NUMBER;
  u->portnum = (uint16_t)port;
  u->port_present = TRUE;
  return CURLUE_OK;
}

/**
 * @brief Set the whole URL from a string (CURLUPART_URL).
 * @internal
 *
 * An absolute URL replaces the existing content. A relative URL is
 * resolved against the URL currently stored in the handle (if complete),
 * following RFC 3986 section 5.2. An empty string is only accepted when a
 * complete URL is already held, and then it just drops the fragment.
 *
 * @param[in,out] u         URL handle.
 * @param[in]     url       The new URL or relative reference.
 * @param[in]     part_size Length of @p url.
 * @param[in]     flags     CURLU_* flags.
 * @return CURLUE_OK on success.
 * @return CURLUE_MALFORMED_INPUT for a blank URL on an incomplete handle.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @return Otherwise a parse error.
 */
static CURLUcode set_url(CURLU *u, const char *url, size_t part_size,
                         unsigned int flags)
{
  /*
   * Allow a new URL to replace the existing (if any) contents.
   *
   * If the existing contents is enough for a URL, allow a relative URL to
   * replace it.
   */
  CURLUcode uc;
  char *oldurl = NULL;

  if(!part_size) {
    /* a blank URL is not a valid URL unless we already have a complete one
       and this is a redirect */
    uc = curl_url_get(u, CURLUPART_URL, &oldurl, flags);
    if(!uc) {
      /* success, meaning the "" is a fine relative URL, and the new URL
         inherits scheme/authority/path/query, but not fragment, from the
         existing URL (RFC 3986 section 5.2.2) */
      curlx_safefree(u->fragment);
      u->fragment_present = FALSE;
      curlx_free(oldurl);
      return CURLUE_OK;
    }
    if(uc == CURLUE_OUT_OF_MEMORY)
      return uc;
    return CURLUE_MALFORMED_INPUT;
  }

  /* if the new URL is absolute replace the existing with the new. */
  if(Curl_is_absolute_url(url, NULL, 0,
                          flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME)))
    return parseurl_and_replace(url, u, flags);

  /* if the old URL is incomplete (we cannot get an absolute URL in
     'oldurl'), replace the existing with the new.
     Always include "scheme://" to make the URL "complete" */
  /* Preserve empty query/fragment separators: they affect where relative
     references splice into the base URL. */
  uc = curl_url_get(u, CURLUPART_URL, &oldurl,
                    (flags & ~CURLU_NO_GUESS_SCHEME) | CURLU_GET_EMPTY);
  if(uc == CURLUE_OUT_OF_MEMORY)
    return uc;
  else if(uc)
    return parseurl_and_replace(url, u, flags);

  DEBUGASSERT(oldurl); /* it is set here */
  /* apply the relative part to create a new URL */
  uc = redirect_url(oldurl, url, u, flags);
  curlx_free(oldurl);
  return uc;
}

/**
 * @brief Clear one component of the handle (set to NULL).
 * @internal
 *
 * CURLUPART_URL clears everything. The password is wiped before freeing.
 *
 * @param[in,out] u    URL handle.
 * @param[in]     what Part to clear.
 * @return CURLUE_OK on success, CURLUE_UNKNOWN_PART for an invalid part.
 */
static CURLUcode urlset_clear(CURLU *u, CURLUPart what)
{
  switch(what) {
  case CURLUPART_URL:
    free_urlhandle(u);
    memset(u, 0, sizeof(struct Curl_URL));
    break;
  case CURLUPART_SCHEME:
    curlx_safefree(u->scheme);
    u->guessed_scheme = FALSE;
    break;
  case CURLUPART_USER:
    curlx_safefree(u->user);
    break;
  case CURLUPART_PASSWORD:
    curlx_strzero(u->password);
    curlx_safefree(u->password);
    break;
  case CURLUPART_OPTIONS:
    curlx_safefree(u->options);
    break;
  case CURLUPART_HOST:
    curlx_safefree(u->host);
    break;
  case CURLUPART_ZONEID:
    curlx_safefree(u->zoneid);
    break;
  case CURLUPART_PORT:
    u->portnum = 0;
    u->port_present = FALSE;
    break;
  case CURLUPART_PATH:
    curlx_safefree(u->path);
    break;
  case CURLUPART_QUERY:
    curlx_safefree(u->query);
    u->query_present = FALSE;
    break;
  case CURLUPART_FRAGMENT:
    curlx_safefree(u->fragment);
    u->fragment_present = FALSE;
    break;
  default:
    return CURLUE_UNKNOWN_PART;
  }
  return CURLUE_OK;
}

/**
 * @brief Tell whether a byte may appear unencoded in a URL path.
 * @internal
 *
 * These are the RFC 3986 sub-delims plus ':', at-sign and '/'.
 *
 * @param[in] x The byte to test.
 * @return TRUE if allowed as-is in a path, else FALSE.
 */
static bool allowed_in_path(unsigned char x)
{
  switch(x) {
  case '!':
  case '$':
  case '&':
  case '\'':
  case '(':
  case ')':
  case '{':
  case '}':
  case '[':
  case ']':
  case '*':
  case '+':
  case ',':
  case ';':
  case '=':
  case ':':
  case '@':
  case '/':
    return TRUE;
  }
  return FALSE;
}

/**
 * @brief Percent-encode a string for use in a URL part.
 * @internal
 *
 * Unreserved characters are kept. Other bytes become %XX, except that
 * a space becomes '+' when @p plusencode is set, path-allowed characters are
 * kept in path mode, and the first '=' is kept when @p equalsencode is set.
 *
 * @param[in,out] encp         Output buffer; encoded data is appended.
 * @param[in]     part         NUL-terminated input.
 * @param[in]     plusencode   Encode space as '+'.
 * @param[in]     pathmode     Keep characters allowed in a path.
 * @param[in]     equalsencode Keep the first '=' (query append mode).
 * @return CURLUE_OK, CURLUE_TOO_LARGE or CURLUE_OUT_OF_MEMORY.
 */
static CURLUcode url_encode_part(struct dynbuf *encp,
                                 const char *part,
                                 bool plusencode,
                                 bool pathmode,
                                 bool equalsencode)
{
  const unsigned char *i;

  for(i = (const unsigned char *)part; *i; i++) {
    CURLcode result;
    if((*i == ' ') && plusencode)
      result = curlx_dyn_addn(encp, "+", 1);
    else if(ISUNRESERVED(*i) ||
            (pathmode && allowed_in_path(*i)) ||
            ((*i == '=') && equalsencode)) {
      if((*i == '=') && equalsencode)
        /* only skip the first equals sign */
        equalsencode = FALSE;
      result = curlx_dyn_addn(encp, i, 1);
    }
    else {
      unsigned char out[3] = { '%' };
      Curl_hexbyte(&out[1], *i);
      result = curlx_dyn_addn(encp, out, 3);
    }
    if(result)
      return cc2cu(result);
  }
  return CURLUE_OK;
}

/**
 * @brief Copy a string, uppercasing the hex of percent sequences.
 * @internal
 *
 * @param[in,out] encp Output buffer; the string is appended and
 *                     normalized in place.
 * @param[in]     part NUL-terminated input.
 * @return CURLUE_OK, CURLUE_TOO_LARGE or CURLUE_OUT_OF_MEMORY.
 */
static CURLUcode url_uppercasehex_part(struct dynbuf *encp,
                                       const char *part)
{
  char *p;
  CURLcode result = curlx_dyn_add(encp, part);
  if(result)
    return cc2cu(result);
  p = curlx_dyn_ptr(encp);
  while(*p) {
    /* make sure percent encoded are upper case */
    if((*p == '%') && ISXDIGIT(p[1]) && ISXDIGIT(p[2]) &&
       (ISLOWER(p[1]) || ISLOWER(p[2]))) {
      p[1] = Curl_raw_toupper(p[1]);
      p[2] = Curl_raw_toupper(p[2]);
      p += 3;
    }
    else
      p++;
  }
  return CURLUE_OK;
}

/**
 * @brief Append a new query part to the existing query.
 * @internal
 *
 * Adds '&' between the old and new data unless the old query already ends
 * with one. Used for CURLU_APPENDQUERY.
 *
 * @param[in,out] u    URL handle whose query is replaced by the result.
 * @param[in,out] encp Encoded data to append; ownership moves to the
 *                     handle on success, freed on failure.
 * @return CURLUE_OK, CURLUE_TOO_LARGE or CURLUE_OUT_OF_MEMORY.
 * @post @p encp must no longer be freed or used by the caller on success.
 */
static CURLUcode url_append_query(CURLU *u, struct dynbuf *encp)
{
  /* Append the 'encp' string onto the old query. Add a '&' separator if none
     is already present at the end of the existing query */

  size_t querylen = u->query ? strlen(u->query) : 0;
  bool addamperand = querylen && (u->query[querylen - 1] != '&');
  if(querylen) {
    struct dynbuf qbuf;
    CURLcode result;
    const char *newp = curlx_dyn_ptr(encp);
    curlx_dyn_init(&qbuf, CURL_MAX_INPUT_LENGTH);

    /* add original query */
    result = curlx_dyn_addn(&qbuf, u->query, querylen);
    if(!result && addamperand)
      /* add ampersand */
      result = curlx_dyn_addn(&qbuf, "&", 1);
    if(!result)
      /* add new query part */
      result = curlx_dyn_add(&qbuf, newp);
    if(result)
      goto nomem;
    curlx_dyn_free(encp);
    curlx_free(u->query);
    u->query = curlx_dyn_ptr(&qbuf);
    return CURLUE_OK;
nomem:
    curlx_dyn_free(encp);
    return cc2cu(result);
  }
  else {
    curlx_free(u->query);
    u->query = curlx_dyn_ptr(encp);
  }
  return CURLUE_OK;
}

/**
 * @brief Validate and normalize a host being set.
 * @internal
 *
 * An empty host is only accepted with CURLU_NO_AUTHORITY. If the host
 * was not URL encoded here it is decoded for the check. IPv6 and IPv4
 * numerical hosts are normalized.
 *
 * @param[in,out] u         URL handle (a zone id may be stored).
 * @param[in,out] encp      Host buffer; may be rewritten. Freed on error.
 * @param[in]     urlencode TRUE if CURLU_URLENCODE was applied.
 * @param[in]     flags     CURLU_* flags.
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_HOSTNAME for an invalid host.
 * @post On error @p encp has been freed.
 */
static CURLUcode url_sethost(CURLU *u, struct dynbuf *encp,
                             bool urlencode,
                             unsigned int flags)
{
  size_t n = curlx_dyn_len(encp);
  bool bad = FALSE;
  char *newp = curlx_dyn_ptr(encp);
  if(!n)
    /* an empty hostname is okay if told so */
    bad = (flags & CURLU_NO_AUTHORITY) ? FALSE : TRUE;
  else if(!urlencode) {
    /* if the hostname part was not URL encoded here, it was set already URL
       encoded so we need to decode it to check */
    size_t dlen;
    char *decoded = NULL;
    CURLcode result = Curl_urldecode(newp, n, &decoded, &dlen, REJECT_CTRL);
    if(result || hostname_check6(u, decoded, dlen))
      bad = TRUE;
    else if(decoded[0] == '[') {
      /* store the normalized IPv6 address, the zone id is kept separately */
      curlx_dyn_reset(encp);
      if(curlx_dyn_add(encp, decoded))
        bad = TRUE;
    }
    else {
      struct dynbuf dbuf;
      curlx_dyn_init(&dbuf, CURL_MAX_INPUT_LENGTH);
      if(curlx_dyn_addn(&dbuf, decoded, dlen))
        bad = TRUE;
      else if(ipv4_normalize(&dbuf) == HOST_IPV4) {
        curlx_dyn_reset(encp);
        if(curlx_dyn_addn(encp, curlx_dyn_ptr(&dbuf), curlx_dyn_len(&dbuf)))
          bad = TRUE;
      }
      curlx_dyn_free(&dbuf);
    }
    curlx_free(decoded);
  }
  else if(hostname_check6(u, newp, n))
    bad = TRUE;
  else if(ipv4_normalize(encp) == HOST_ERROR)
    bad = TRUE;
  if(bad) {
    curlx_dyn_free(encp);
    return CURLUE_BAD_HOSTNAME;
  }
  return CURLUE_OK;
}

/**
 * @brief Set or replace a part of the URL in a handle.
 * @ingroup urlapi
 *
 * Passing NULL as @p part clears the component. The new content is
 * copied into the handle. With CURLU_URLENCODE the data is encoded;
 * otherwise percent-encoded hex is just uppercased. The path always gets a
 * leading slash and the host is validated and normalized.
 *
 * @param[in,out] u     URL handle.
 * @param[in]     what  The part to set (CURLUPART_*).
 * @param[in]     part  New content, or NULL to clear it.
 * @param[in]     flags CURLU_* flags (CURLU_URLENCODE, CURLU_APPENDQUERY,
 *                      CURLU_NON_SUPPORT_SCHEME, CURLU_GUESS_SCHEME,
 *                      CURLU_DEFAULT_SCHEME, CURLU_NO_AUTHORITY, ...).
 * @return CURLUE_OK on success.
 * @return CURLUE_BAD_HANDLE if @p u is NULL.
 * @return CURLUE_MALFORMED_INPUT if the input is longer than
 *         CURL_MAX_INPUT_LENGTH.
 * @return CURLUE_UNKNOWN_PART for an unknown @p what.
 * @return CURLUE_BAD_PORT_NUMBER, CURLUE_BAD_SCHEME,
 *         CURLUE_UNSUPPORTED_SCHEME, CURLUE_BAD_HOSTNAME or another
 *         part-specific error for bad input.
 * @return CURLUE_OUT_OF_MEMORY on allocation failure.
 * @warning Not thread-safe for a shared handle. On failure the previous
 *          content of the part is preserved.
 * @see curl_url_get()
 */
CURLUcode curl_url_set(CURLU *u, CURLUPart what,
                       const char *part, unsigned int flags)
{
  char **storep = NULL;
  bool urlencode = (flags & CURLU_URLENCODE) ? 1 : 0;
  bool plusencode = FALSE;
  bool pathmode = FALSE;
  bool leadingslash = FALSE;
  bool appendquery = FALSE;
  bool equalsencode = FALSE;
  size_t nalloc;

  if(!u)
    return CURLUE_BAD_HANDLE;
  if(!part)
    /* setting a part to NULL clears it */
    return urlset_clear(u, what);

  nalloc = strlen(part);
  if(nalloc > CURL_MAX_INPUT_LENGTH)
    /* excessive input length */
    return CURLUE_MALFORMED_INPUT;

  /* Pick where to store the data and how it must be encoded. */
  switch(what) {
  case CURLUPART_SCHEME: {
    CURLUcode status = set_url_scheme(u, part, flags);
    if(status)
      return status;
    storep = &u->scheme;
    urlencode = FALSE; /* never */
    break;
  }
  case CURLUPART_USER:
    storep = &u->user;
    break;
  case CURLUPART_PASSWORD:
    storep = &u->password;
    break;
  case CURLUPART_OPTIONS:
    storep = &u->options;
    break;
  case CURLUPART_HOST:
    storep = &u->host;
    curlx_safefree(u->zoneid);
    break;
  case CURLUPART_ZONEID:
    storep = &u->zoneid;
    break;
  case CURLUPART_PORT:
    return set_url_port(u, part);
  case CURLUPART_PATH:
    pathmode = TRUE;
    leadingslash = TRUE; /* enforce */
    storep = &u->path;
    break;
  case CURLUPART_QUERY:
    plusencode = urlencode;
    appendquery = (flags & CURLU_APPENDQUERY) ? 1 : 0;
    equalsencode = appendquery;
    storep = &u->query;
    u->query_present = TRUE;
    break;
  case CURLUPART_FRAGMENT:
    storep = &u->fragment;
    u->fragment_present = TRUE;
    break;
  case CURLUPART_URL:
    return set_url(u, part, nalloc, flags);
  default:
    return CURLUE_UNKNOWN_PART;
  }
  /* Build the encoded copy and swap it in for the old content. */
  DEBUGASSERT(storep);
  {
    const char *newp = NULL;
    struct dynbuf enc;
    CURLUcode status;
    curlx_dyn_init(&enc, (what == CURLUPART_HOST) ?
                   CURLMAX((nalloc * 3) + 1 + leadingslash, 16) :
                   (nalloc * 3) + 1 + leadingslash);

    if(leadingslash && (part[0] != '/')) {
      CURLcode result = curlx_dyn_addn(&enc, "/", 1);
      if(result)
        return cc2cu(result);
    }
    if(urlencode)
      status = url_encode_part(&enc, part, plusencode, pathmode, equalsencode);
    else
      status = url_uppercasehex_part(&enc, part);
    if(!status) {
      newp = curlx_dyn_ptr(&enc);

      if(appendquery && newp)
        return url_append_query(u, &enc);
      else if(what == CURLUPART_HOST)
        status = url_sethost(u, &enc, urlencode, flags);
    }
    if(status)
      return status;

    if(what == CURLUPART_PASSWORD)
      curlx_strzero(*storep);
    curlx_free(*storep);
    *storep = (char *)CURL_UNCONST(newp);
  }
  return CURLUE_OK;
}

/**
 * @brief Check whether two URLs have the same origin.
 *
 * Compares scheme, host, port (a default port matches a missing one) and
 * zone id. Used to decide, for example, whether credentials may be sent on
 * after a redirect.
 *
 * @param[in] base The base URL; must be absolute (scheme and host).
 * @param[in] href The URL to compare; may be partial.
 * @return TRUE if @p href is same-origin with @p base, FALSE otherwise.
 * @note A partial @p href (missing scheme or host) inherits from @p base.
 */
bool Curl_url_same_origin(CURLU *base, CURLU *href)
{
  const struct Curl_scheme *s = NULL;

  /* base must be an absolute URL */
  if(!base->scheme || !base->host)
    return FALSE;
  if(href->scheme && !curl_strequal(base->scheme, href->scheme))
    return FALSE;
  if(href->host) {
    if(!curl_strequal(base->host, href->host))
      return FALSE;

    if(base->port_present != href->port_present) {
      /* one is present, one is not */
      s = Curl_get_scheme(base->scheme);
      if(!s) /* Cannot match default port for unknown scheme */
        return FALSE;
      /* to match, the present one must be the default port */
      if((base->port_present && (base->portnum != s->defport)) ||
         (href->port_present && (href->portnum != s->defport)))
        return FALSE;
    }
    else if(base->portnum != href->portnum) /* both present or missing */
      return FALSE;

    if(!curl_strequal(base->zoneid ? base->zoneid : "",
                      href->zoneid ? href->zoneid : ""))
      return FALSE;
  }
  else if(href->port_present) /* no host in href, then there must be no port */
    return FALSE;
  return TRUE;
}

/**
 * @brief Get the port of a handle, falling back to the scheme default.
 *
 * @param[in]  u     URL handle.
 * @param[out] pport Receives the port number, 0 if none is available.
 * @return CURLUE_OK if a port is stored or the scheme has a default.
 * @return CURLUE_NO_PORT otherwise.
 */
CURLUcode Curl_url_get_port(CURLU *u, uint16_t *pport)
{
  if(u->port_present) {
    *pport = u->portnum;
    return CURLUE_OK;
  }
  else if(u->scheme) {
    const struct Curl_scheme *s = Curl_get_scheme(u->scheme);
    if(s && s->defport) {
      *pport = s->defport;
      return CURLUE_OK;
    }
  }
  *pport = 0;
  return CURLUE_NO_PORT;
}

/** @} */
