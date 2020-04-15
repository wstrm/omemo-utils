// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "stream.h"
#include <stdio.h>

#define AES256_GCM_KEY_LENGTH 32
#define AES256_GCM_NONCE_LENGTH 12

int aes256gcm_init(void);
int aes256gcm_encrypt(STREAM *in, FILE *out, unsigned char key[],
                      unsigned char nonce[]);
int aes256gcm_decrypt(STREAM *in, FILE *out, unsigned char key[],
                      unsigned char nonce[]);
