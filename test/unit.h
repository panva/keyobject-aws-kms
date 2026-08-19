/* A deliberately small test harness: these are unit tests for local parsing
 * logic, and anything bigger would be its own maintenance burden. */
#ifndef AWSKMS_TEST_UNIT_H
#define AWSKMS_TEST_UNIT_H

#include <stdio.h>
#include <string.h>

extern int awskms_test_failures;
extern int awskms_test_checks;

#define CHECK(cond, ...)                                     \
  do {                                                       \
    awskms_test_checks++;                                    \
    if (!(cond)) {                                           \
      awskms_test_failures++;                                \
      fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, __VA_ARGS__);                          \
      fprintf(stderr, "\n");                                 \
    }                                                        \
  } while (0)

#define CHECK_STR(actual, expected, what)                        \
  do {                                                           \
    const char *a_ = (actual), *e_ = (expected);                 \
    if (e_ == NULL) {                                            \
      CHECK(a_ == NULL, "%s: expected NULL, got \"%s\"", (what), \
            a_ ? a_ : "(null)");                                 \
    } else {                                                     \
      CHECK(a_ != NULL && strcmp(a_, e_) == 0,                   \
            "%s: expected \"%s\", got \"%s\"", (what), e_,       \
            a_ ? a_ : "(null)");                                 \
    }                                                            \
  } while (0)

void test_uri(void);
void test_keyspec(void);
void test_spki(void);
void test_mu(void);

#endif /* AWSKMS_TEST_UNIT_H */
