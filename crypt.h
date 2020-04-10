#include <stdio.h>

int aes256gcm_init(void);
int aes256gcm_encrypt(FILE *in, FILE *out);
int aes256gcm_decrypt(FILE *in, FILE *out);
