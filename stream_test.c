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

  unsigned char key[AESGCM_URL_KEY_SIZE];
  unsigned char nonce[AESGCM_URL_NONCE_SIZE];

  char *parsed_url;
  parsed_url = parse_aesgcm_url(raw_url, nonce, key);

  assert(parsed_url != NULL);
  assert(strcmp(parsed_url, expected_url) == 0);

  free(parsed_url);
}

int main(int argc, char **argv) { test_parse_aesgcm_url(); }
