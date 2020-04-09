#include <assert.h>
#include <gcrypt.h>
#include <stdio.h>

#define AES256_GCM_KEY_LENGTH 32
#define AES256_GCM_NONCE_LENGTH 12
#define AES256_GCM_TAG_LENGTH 16
#define AES256_GCM_BUFFER_SIZE 1024

int aes256gcm_crypt(FILE *in, FILE *out, int encrypt) {
  unsigned char key[] = "0123456789abcdef0123456789abcdef";
  unsigned char nonce[] = "123456788765";

  gcry_error_t res;
  gcry_cipher_hd_t hd;

  /* Create context handle with AES256 GCM. */
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

  int bytes;
  for (;;) {
    bytes = fread(buffer, 1, AES256_GCM_BUFFER_SIZE, in);
    if (!bytes)
      break; // EOF.

    if (bytes < AES256_GCM_BUFFER_SIZE) {
      gcry_cipher_final(hd); // Signal last round of bytes.
    }

    if (encrypt) {
      res = gcry_cipher_encrypt(hd, buffer, bytes, NULL, 0);
    } else {
      res = gcry_cipher_decrypt(hd, buffer, bytes, NULL, 0);
    }

    if (res != GPG_ERR_NO_ERROR) {
      break;
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
    fseek(in, -AES256_GCM_TAG_LENGTH, SEEK_END);
    bytes = fread(tag, 1, AES256_GCM_TAG_LENGTH, in);

    res = gcry_cipher_checktag(hd, tag, bytes);
  }

out:
  gcry_cipher_close(hd);
  return res;
}

int aes256gcm_encrypt(FILE *in, FILE *out) {
  return aes256gcm_crypt(in, out, 1);
}

int aes256gcm_decrypt(FILE *in, FILE *out) {
  return aes256gcm_crypt(in, out, 0);
}

int main(int argc, char **argv) {
  FILE *in_plain = fopen("file.txt", "r");
  FILE *out_crypt = fopen("file.aes", "w");

  aes256gcm_encrypt(in_plain, out_crypt);

  fclose(in_plain);
  fclose(out_crypt);

  FILE *in_crypt = fopen("file.aes", "r");
  FILE *out_plain = fopen("result.txt", "w");

  int res;
  res = aes256gcm_decrypt(in_crypt, out_plain);

  fclose(in_crypt);
  fclose(out_plain);

  if (res == GPG_ERR_CHECKSUM) {
    printf("Checksum failed");
  }
}
