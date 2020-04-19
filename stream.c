// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "stream.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define AESGCM_URL_SCHEME "aesgcm://"
#define AESGCM_URL_SCHEME_LEN (size_t)(sizeof(AESGCM_URL_SCHEME) - 1)
#define AESGCM_URL_FRAGMENT_LEN                                                \
  (size_t)(AESGCM_URL_NONCE_LEN + AESGCM_URL_KEY_LEN)

#define HEADER_CL "Content-Length: "
#define HEADER_CL_LEN (size_t)(sizeof(HEADER_CL) - 1)

static size_t write_callback(void *data, size_t size, size_t nmemb,
                             void *userdata) {
  size *= nmemb;
  STREAM *stream = (STREAM *)userdata;

  // Grow buffer to fit the response size.
  char *buffer = realloc(stream->buffer, stream->actual_size + size + 1);
  if (buffer == NULL) {
    return 0; // OOM.
  }

  stream->buffer = buffer;

  memcpy(&(stream->buffer[stream->actual_size]), data, size);

  stream->actual_size += size;
  stream->buffer[stream->actual_size] = 0;

  return size;
}

static size_t header_callback(char *data, size_t size, size_t nitems,
                              void *userdata) {
  STREAM *stream = (STREAM *)userdata;
  size *= nitems;

  if (stream->expected_size > 0) {
    return size; // No-op.
  }

  if (strncmp(data, HEADER_CL, HEADER_CL_LEN) == 0) {
    stream->expected_size = strtoul(&(data[HEADER_CL_LEN]), NULL, 10);
  }

  return size;
}

void bytes_from_hex(char *hex, unsigned char *bytes, size_t bytes_size) {
  const unsigned char ht[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
      0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
      0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
  };

  unsigned char b0;
  unsigned char b1;

  size_t hex_len = strlen(hex);

  memset(bytes, 0, bytes_size);

  for (int i = 0; (i < hex_len) && (i / 2 < bytes_size); i += 2) {
    b0 = ((unsigned char)hex[i + 0] & 0x1f) ^ 0x10;
    b1 = ((unsigned char)hex[i + 1] & 0x1f) ^ 0x10;

    bytes[i / 2] = (unsigned char)(ht[b0] << 4) | ht[b1];
  }
}

char *parse_aesgcm_url(char *url, unsigned char *nonce, size_t nonce_size,
                       unsigned char *key, size_t key_size) {

  size_t url_len = strlen(url);
  size_t url_size = url_len + 1;

  char nonce_hex[AESGCM_URL_NONCE_LEN];
  char key_hex[AESGCM_URL_KEY_LEN];

  size_t nonce_pos;
  size_t key_pos;

  char *resource;
  size_t resource_len;
  size_t resource_pos;

  // Must allocate at least the size of the URL and the HTTPS scheme length.
  resource = (char *)malloc(url_size + HTTPS_URL_SCHEME_LEN);
  if (resource == NULL) {
    fprintf(stderr, "parse_aesgcm_url() failed to allocate memory");
    abort();
  }

  if (strncmp(url, AESGCM_URL_SCHEME, AESGCM_URL_SCHEME_LEN) == 0) {
    // Nonce is 24 characters, key is 64 characters, giving a total of 88
    // characters. Plus the protocol scheme length and fragment character.
    if (url_len <= AESGCM_URL_SCHEME_LEN + AESGCM_URL_FRAGMENT_LEN + 1) {
      goto out;
    }

    nonce_pos = strcspn(url, "#") + 1;

    // The fragment length must equal the expected AESGCM fragment length.
    if (url_len - nonce_pos != AESGCM_URL_FRAGMENT_LEN) {
      goto out;
    }

    key_pos = nonce_pos + AESGCM_URL_NONCE_LEN;
    resource_pos = AESGCM_URL_SCHEME_LEN;
    resource_len = url_len - AESGCM_URL_FRAGMENT_LEN - resource_pos - 1;

    strcpy(resource, HTTPS_URL_SCHEME);
    strncat(resource, &(url[resource_pos]), resource_len);

    strncpy(nonce_hex, &(url[nonce_pos]), AESGCM_URL_NONCE_LEN);
    strncpy(key_hex, &(url[key_pos]), AESGCM_URL_KEY_LEN);

    bytes_from_hex(nonce_hex, nonce, nonce_size);
    bytes_from_hex(key_hex, key, key_size);

    return resource;
  }

out:
  free(resource);
  return NULL;
}

STREAM *stream_open(const char *url) {
  CURLcode res;

  STREAM *stream;
  stream = calloc(1, sizeof(STREAM));
  if (!stream) {
    return NULL;
  }

  CURL *hd = curl_easy_init();
  if (hd == NULL) {
    free(stream);
    return NULL;
  }

  curl_easy_setopt(hd, CURLOPT_URL, url);

  curl_easy_setopt(hd, CURLOPT_HEADERFUNCTION, header_callback);
  curl_easy_setopt(hd, CURLOPT_HEADERDATA, (void *)stream);

  curl_easy_setopt(hd, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(hd, CURLOPT_WRITEDATA, (void *)stream);

  res = curl_easy_perform(hd);
  if (res != CURLE_OK) {
    free(stream);
    return NULL;
  }

  return stream;
}

size_t stream_read(void *buffer, size_t bytes, STREAM *stream) {
  if (!stream->actual_size || stream->actual_size == stream->buffer_pos) {
    return 0; // Empty or EOF.
  }

  size_t start_pos = stream->buffer_pos;
  size_t end_pos = start_pos + bytes;

  // Make sure we do not read outside of the available stream buffer.
  if (stream->actual_size < end_pos) {
    bytes = stream->actual_size - start_pos;
    end_pos = start_pos + bytes;
  }

  memcpy(buffer, &(stream->buffer[start_pos]), bytes);
  stream->buffer_pos = end_pos;

  return bytes;
}
