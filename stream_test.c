#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

void test_parse_aesgcm_url() {
  char expected_url[] = "https://example.org";
  unsigned char expected_nonce[AESGCM_URL_NONCE_LEN / 2] = {
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x00, 0x00, 0x00};
  unsigned char expected_key[AESGCM_URL_KEY_LEN / 2] = {
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x00, 0x00,
      0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x00,
      0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};

  char raw_url[] =
      "aesgcm://"
      "example.org#"
      "123456789ABCdef000000000" // Nonce
      "123456789abcDEF000000000123456789aBCDEf000000000123456789AbcdeF0"; // Key

  unsigned char key[AESGCM_URL_KEY_LEN / 2];
  unsigned char nonce[AESGCM_URL_NONCE_LEN / 2];

  char *parsed_url;
  parsed_url =
      parse_aesgcm_url(raw_url, nonce, sizeof(nonce), key, sizeof(key));

  assert(parsed_url != NULL);
  assert(strcmp(parsed_url, expected_url) == 0);
  assert(memcmp(nonce, expected_nonce, sizeof(nonce)) == 0);
  assert(memcmp(key, expected_key, sizeof(key)) == 0);

  free(parsed_url);
}

int main(int argc, char **argv) { test_parse_aesgcm_url(); }
