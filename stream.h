// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include <curl/curl.h>
#include <stdbool.h>

struct stream_data {
  char *buffer;
  size_t buffer_pos;
  size_t actual_size;
  size_t expected_size;
};

typedef struct stream_data STREAM;

size_t stream_read(void *buffer, size_t bytes, STREAM *stream);
STREAM *stream_open(const char *url);
