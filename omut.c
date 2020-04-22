// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "crypt.h"
#include <errno.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum direction { ENCRYPT, DECRYPT };

#define EXIT_INVALID_CHECKSUM 2
#define EXIT_BAD_FILE 3
#define EXIT_FAIL_READ 4
#define EXIT_NO_MEM 5

int gcry_init(void) {
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  return 0;
}

void print_crypto_material(char *type, unsigned char *material, int len) {
  fprintf(stderr, "%s: ", type);
  for (int i = 0; i < len; i++) {
    fprintf(stderr, "%02x", material[i]);
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

  gcry_init();

  unsigned char nonce[AES256_GCM_NONCE_LENGTH];
  unsigned char *key = gcry_malloc_secure(AES256_GCM_KEY_LENGTH);
  if (key == NULL) {
    fputs("Out of memory\n", stderr);
    exit(EXIT_NO_MEM);
  }

  STREAM *in_stream;
  char *raw_url = strdup(argv[optind]);

  int crypt_res = GPG_ERR_NO_ERROR;
  int exit_status = EXIT_SUCCESS;

  char *parsed_url;
  parsed_url = parse_aesgcm_url(raw_url, nonce, AES256_GCM_NONCE_LENGTH, key,
                                AES256_GCM_KEY_LENGTH);
  if (parsed_url == NULL && errno == ENOMEM) {
    exit_status = EXIT_NO_MEM;
    fputs("Out of memory\n", stderr);
    goto out;
  }

  if (parsed_url == NULL) {
    key = gcry_random_bytes_secure(AES256_GCM_KEY_LENGTH,
                                   GCRY_VERY_STRONG_RANDOM);
    gcry_create_nonce(nonce, AES256_GCM_NONCE_LENGTH);
    in_stream = stream_open(raw_url);
  } else {
    in_stream = stream_open(parsed_url);
  }

  free(parsed_url);
  free(raw_url);

  if (in_stream == NULL) {
    exit_status = EXIT_FAIL_READ;
    fputs("Failed to read input\n", stderr);
    goto out;
  }

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

out:
  gcry_free(key);
  exit(exit_status);
}
