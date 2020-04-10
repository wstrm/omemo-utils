#include "crypt.h"
#include <bsd/string.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum DIRECTION { ENCRYPT, DECRYPT };

#define EXIT_INVALID_CHECKSUM 2

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
    fprintf(stderr, "Usage: %s [-d] FILE\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *in_path = strdup(argv[optind]);
  FILE *in_fd = fopen(in_path, "rb");
  free(in_path);

  int crypt_res = GPG_ERR_NO_ERROR;
  int exit_status = EXIT_SUCCESS;

  aes256gcm_init();

  if (direction == ENCRYPT) {
    crypt_res = aes256gcm_encrypt(in_fd, stdout);
  } else /* direction == DECRYPT */ {
    crypt_res = aes256gcm_decrypt(in_fd, stdout);
  }

  if (crypt_res == GPG_ERR_CHECKSUM) {
    fprintf(stderr, "Invalid checksum (#%d)\n", crypt_res);
    exit_status = EXIT_INVALID_CHECKSUM;
  }

  fclose(in_fd);
  exit(exit_status);
}
