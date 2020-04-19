// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "crypt.h"
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum direction { ENCRYPT, DECRYPT };

#define EXIT_INVALID_CHECKSUM 2
#define EXIT_BAD_FILE 3

void print_crypto_material(char *type, unsigned char *material, int len) {
  fprintf(stderr, "%s: ", type);
  for (int i = 0; i < len; i++) {
    fprintf(stderr, "%x", material[i]);
  }
  fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
  int opt;
  int direction = ENCRYPT;

  while ((opt = getopt(argc, argv, "d+")) != -1) {
    switch (opt) {
    case 'd':
      direction = DECRYPT;
      break;
    default:
      direction = ENCRYPT;
    }
  }

  if (optind + 1 != argc) {
    fprintf(stderr, "Usage: %s [-d] URL\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *raw_url = strdup(argv[optind]);
  char *parsed_url = malloc(sizeof(raw_url) + HTTPS_URL_SCHEME_LEN);

  unsigned char *key = malloc(AES256_GCM_KEY_LENGTH);
  unsigned char nonce[AES256_GCM_NONCE_LENGTH];

  aes256gcm_init();

  if (parse_aesgcm_url(raw_url, parsed_url, sizeof(parsed_url), nonce, key) !=
      0) {
    key = gcry_random_bytes(AES256_GCM_KEY_LENGTH, GCRY_VERY_STRONG_RANDOM);
    gcry_create_nonce(nonce, AES256_GCM_NONCE_LENGTH);
  }

  STREAM *in_stream = stream_open(parsed_url);

  free(parsed_url);
  free(raw_url);

  int crypt_res = GPG_ERR_NO_ERROR;
  int exit_status = EXIT_SUCCESS;

  if (direction == ENCRYPT) {
    crypt_res = aes256gcm_encrypt(in_stream, stdout, key, nonce);
  } else /* direction == DECRYPT */ {
    crypt_res = aes256gcm_decrypt(in_stream, stdout, key, nonce);
  }

  if (crypt_res == GPG_ERR_CHECKSUM) {
    fprintf(stderr, "Invalid checksum (#%d)\n", crypt_res);
    exit_status = EXIT_INVALID_CHECKSUM;
  } else if (crypt_res != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Bad file (#%d)\n", crypt_res);
    exit_status = EXIT_BAD_FILE;
  }

  print_crypto_material("Key", key, AES256_GCM_KEY_LENGTH);
  print_crypto_material("Nonce", nonce, AES256_GCM_NONCE_LENGTH);

  free(key);

  exit(exit_status);
}