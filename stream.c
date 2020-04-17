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
  (size_t)(AESGCM_URL_NONCE_SIZE + AESGCM_URL_KEY_SIZE)

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

int parse_aesgcm_url(char *url, char *resource, size_t resource_size,
                     char nonce[AESGCM_URL_NONCE_SIZE],
                     char key[AESGCM_URL_KEY_SIZE]) {

  size_t url_len = strlen(url);
  size_t nonce_pos;
  size_t key_pos;
  size_t resource_len;
  size_t resource_pos;

  // Must allocate at least the size of the URL.
  if (resource_size < url_len) {
    return -1;
  }

  if (strncmp(url, AESGCM_URL_SCHEME, AESGCM_URL_SCHEME_LEN) == 0) {
    // Nonce is 24 characters, key is 64 characters, giving a total of 88
    // characters. Plus the protocol scheme length and fragment character.
    if (url_len <= AESGCM_URL_SCHEME_LEN + AESGCM_URL_FRAGMENT_LEN + 1) {
      return -1;
    }

    nonce_pos = strcspn(url, "#") + 1;
    key_pos = nonce_pos + AESGCM_URL_KEY_SIZE;
    resource_pos = AESGCM_URL_SCHEME_LEN;
    resource_len = url_len - AESGCM_URL_FRAGMENT_LEN - resource_pos - 1;

    strncpy(resource, &(url[resource_pos]), resource_len);
    strncpy(nonce, &(url[nonce_pos]), AESGCM_URL_NONCE_SIZE);
    strncpy(key, &(url[key_pos]), AESGCM_URL_KEY_SIZE);

    return 0;
  }

  return -1;
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
