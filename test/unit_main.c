#include "unit.h"

int awskms_test_failures;
int awskms_test_checks;

int main(void) {
  /* Unbuffered, so a crash inside a suite does not swallow the log telling you
   * which suite it was. */
  setvbuf(stdout, NULL, _IONBF, 0);

  struct {
    const char *name;
    void (*fn)(void);
  } suites[] = {{"uri", test_uri},
                {"keyspec", test_keyspec},
                {"spki", test_spki},
                {"mu", test_mu}};

  for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
    int before = awskms_test_failures;
    printf("%s\n", suites[i].name);
    suites[i].fn();
    printf("  %s\n", awskms_test_failures == before ? "ok" : "FAILED");
  }

  printf("\n%d checks, %d failures\n", awskms_test_checks,
         awskms_test_failures);
  return awskms_test_failures == 0 ? 0 : 1;
}
