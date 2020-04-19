#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

void test_parse_aesgcm_url() {
  char raw_url[] = "aesgcm://"
                   "example.org#"
                   "11231231231231231231231231231232312312312312312312312312312"
                   "31231231231231231231231212343";

  char expected_url[] = "https://example.org";

  char parsed_url[sizeof(raw_url) + HTTPS_URL_SCHEME_LEN];

  unsigned char key[64];
  unsigned char nonce[24];

  assert(parse_aesgcm_url(raw_url, parsed_url, sizeof(parsed_url), nonce,
                          key) == 0);

  assert(strcmp(parsed_url, expected_url) == 0);
}

int main(int argc, char **argv) { test_parse_aesgcm_url(); }
