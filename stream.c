// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "stream.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/*
off_t fsize(FILE *file) {
  struct stat st;

  int fd = fileno(file);
  if (fd < 0) {
    return -1;
  }

  if (fstat(fd, &st) == 0) {
    return st.st_size;
  }

  return -1;
}
*/

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

  char header[] = "Content-Length: ";
  size_t header_len = sizeof(header) - 1;

  if (strncmp(data, header, header_len) == 0) {
    stream->expected_size = strtoul(&(data[header_len]), NULL, 10);
  }

  return size;
}

STREAM *stream_open(const char *url) {
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

  curl_easy_perform(hd);

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
