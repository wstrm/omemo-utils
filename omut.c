#include "crypt.h"
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum direction { ENCRYPT, DECRYPT };

#define EXIT_INVALID_CHECKSUM 2
#define EXIT_BAD_FILE 3

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

  char *in_path;
  STREAM *in_stream;

  in_path = strdup(argv[optind]);
  in_stream = stream_open(in_path);

  free(in_path);

  int crypt_res = GPG_ERR_NO_ERROR;
  int exit_status = EXIT_SUCCESS;

  aes256gcm_init();

  if (direction == ENCRYPT) {
    crypt_res = aes256gcm_encrypt(in_stream, stdout);
  } else /* direction == DECRYPT */ {
    crypt_res = aes256gcm_decrypt(in_stream, stdout);
  }

  if (crypt_res == GPG_ERR_CHECKSUM) {
    fprintf(stderr, "Invalid checksum (#%d)\n", crypt_res);
    exit_status = EXIT_INVALID_CHECKSUM;
  } else if (crypt_res != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Bad file (#%d)\n", crypt_res);
    exit_status = EXIT_BAD_FILE;
  }

  exit(exit_status);
}
