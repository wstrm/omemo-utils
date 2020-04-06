#include <assert.h>
#include <stdio.h>
#include <gcrypt.h>

#define AES256_GCM_KEY_LENGTH 16
#define AES256_GCM_IV_LENGTH 12
#define AES256_GCM_BUFFER_SIZE 1024

int
aes256gcm_crypt(FILE *in, FILE *out, int encrypt)
{
  unsigned char key[] = "0123456789abcdef";
  unsigned char iv[] = "1234567887654321";

  gcry_error_t res;
  gcry_cipher_hd_t hd;

  /* Create context handle with AES256 GCM. */
  res = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, GCRY_CIPHER_SECURE);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  res = gcry_cipher_setkey(hd, key, AES256_GCM_KEY_LENGTH);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  res = gcry_cipher_setiv(hd, iv, AES256_GCM_IV_LENGTH);
  if (res != GPG_ERR_NO_ERROR) {
    goto out;
  }

  unsigned char buffer[AES256_GCM_BUFFER_SIZE];

  int bytes;
  for(;;) {
    bytes = fread(buffer, 1, AES256_GCM_BUFFER_SIZE, in);
    if (!bytes) break; // EOF.

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

out:
  gcry_cipher_close(hd);
  return res;
}

int
aes256gcm_encrypt(FILE *in, FILE *out)
{
  return aes256gcm_crypt(in, out, 1);
}

int
aes256gcm_decrypt(FILE *in, FILE *out)
{
  return aes256gcm_crypt(in, out, 0);
}

int main(int argc, char **argv)
{
  FILE *in_plain = fopen("file.txt", "r");
  FILE *out_crypt = fopen("file.aes", "w");

  aes256gcm_encrypt(in_plain, out_crypt);

  fclose(in_plain);
  fclose(out_crypt);

  FILE *in_crypt = fopen("file.aes", "r");
  FILE *out_plain = fopen("result.txt", "w");

  aes256gcm_encrypt(in_crypt, out_plain);

  fclose(in_crypt);
  fclose(out_plain);
}
