// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include <curl/curl.h>
#include <stdbool.h>

#define AESGCM_URL_NONCE_LEN 24
#define AESGCM_URL_KEY_LEN 64

#define HTTPS_URL_SCHEME "https://"
#define HTTPS_URL_SCHEME_LEN (size_t)(sizeof("https://") - 1)

struct stream_data {
  char *buffer;
  size_t buffer_pos;
  size_t actual_size;
  size_t expected_size;
};

typedef struct stream_data STREAM;

size_t stream_read(void *buffer, size_t bytes, STREAM *stream);
STREAM *stream_open(const char *url);
char *parse_aesgcm_url(char *url, unsigned char *nonce, size_t nonce_size,
                       unsigned char *key, size_t key_size);
