#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

void test_parse_aesgcm_url() {
  char expected_url[] = "https://example.org";

  char raw_url[] = "aesgcm://"
                   "example.org#"
                   "11231231231231231231231231231232312312312312312312312312312"
                   "31231231231231231231231212343";
  size_t raw_url_size = sizeof(raw_url);

  size_t parsed_url_size = raw_url_size + HTTPS_URL_SCHEME_LEN;
  char parsed_url[parsed_url_size];

  unsigned char key[AESGCM_URL_NONCE_SIZE];
  unsigned char nonce[AESGCM_URL_KEY_SIZE];

  assert(parse_aesgcm_url(raw_url, raw_url_size, parsed_url, parsed_url_size,
                          nonce, key) == 0);

  assert(strcmp(parsed_url, expected_url) == 0);
}

int main(int argc, char **argv) { test_parse_aesgcm_url(); }
