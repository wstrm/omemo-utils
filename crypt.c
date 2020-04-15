// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "crypt.h"
#include <assert.h>
#include <gcrypt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define AES256_GCM_TAG_LENGTH 16
#define AES256_GCM_BUFFER_SIZE 1024

int aes256gcm_crypt(STREAM *in, FILE *out, unsigned char key[],
                    unsigned char nonce[], bool encrypt) {

  if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
    fputs("libgcrypt has not been initialized\n", stderr);
    abort();
  }

  off_t file_size = in->expected_size;
  if (!encrypt) {
    file_size -= AES256_GCM_TAG_LENGTH;
  }

  gcry_error_t res;
  gcry_cipher_hd_t hd;

  res = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM,
                         GCRY_CIPHER_SECURE);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  res = gcry_cipher_setkey(hd, key, AES256_GCM_KEY_LENGTH);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  res = gcry_cipher_setiv(hd, nonce, AES256_GCM_NONCE_LENGTH);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  unsigned char buffer[AES256_GCM_BUFFER_SIZE];

  int bytes = 0;
  off_t bytes_read = 0, bytes_available = 0, read_size = 0;
  while (bytes_read < file_size) {
    bytes_available = file_size - bytes_read;
    if (!bytes_available) {
      break;
    }

    if (bytes_available < AES256_GCM_BUFFER_SIZE) {
      read_size = bytes_available;
      gcry_cipher_final(hd); // Signal last round of bytes.
    } else {
      read_size = AES256_GCM_BUFFER_SIZE;
    }

    bytes = stream_read(buffer, read_size, in);
    bytes_read += bytes;

    if (encrypt) {
      res = gcry_cipher_encrypt(hd, buffer, bytes, NULL, 0);
    } else {
      res = gcry_cipher_decrypt(hd, buffer, bytes, NULL, 0);
    }

    if (res != GPG_ERR_NO_ERROR) {
      goto out;
    }

    fwrite(buffer, 1, bytes, out);
  }

  unsigned char tag[AES256_GCM_TAG_LENGTH];

  if (encrypt) {
    // Append authentication tag at the end of the file.
    res = gcry_cipher_gettag(hd, tag, AES256_GCM_TAG_LENGTH);
    if (res != GPG_ERR_NO_ERROR) {
      goto out;
    }

    fwrite(tag, 1, AES256_GCM_TAG_LENGTH, out);

  } else {
    // Read and verify authentication tag stored at the end of the file.
    bytes = stream_read(tag, AES256_GCM_TAG_LENGTH, in);
    res = gcry_cipher_checktag(hd, tag, bytes);
  }

out:
  gcry_cipher_close(hd);
  return res;
}

int aes256gcm_init(void) {
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  return 0;
}

int aes256gcm_encrypt(STREAM *in, FILE *out, unsigned char key[],
                      unsigned char nonce[]) {
  return aes256gcm_crypt(in, out, key, nonce, true);
}

int aes256gcm_decrypt(STREAM *in, FILE *out, unsigned char key[],
                      unsigned char nonce[]) {
  return aes256gcm_crypt(in, out, key, nonce, false);
}
