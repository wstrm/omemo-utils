// SPDX-License-Identifier: MIT
// Copyright (c) 2020 William Wennerström

#include "stream.h"
#include <stdio.h>

int aes256gcm_init(void);
int aes256gcm_encrypt(STREAM *in, FILE *out);
int aes256gcm_decrypt(STREAM *in, FILE *out);
