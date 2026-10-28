/* Expected results come from the reference util.san_ref / san_sha, run over
   this corpus (RNS commit e40191b3). One difference is deliberate and left out:
   the reference accepts whitespace inside a SHA (bytes.fromhex skips it); this
   code does not. */
#include "../examples/rngit_common.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
typedef struct c { int ok; const char *text; } c;
static const c refs[] = {
  {1, "refs/heads/main"},
  {1, "refs/tags/v1.0"},
  {0, "-refs/heads/x"},
  {0, "/refs/heads/x"},
  {0, "refs/heads/x/"},
  {0, "refs/heads/x."},
  {0, "refs heads/x"},
  {0, "main"},
  {0, "refs/../x"},
  {0, "refs/heads/.hidden"},
  {0, "refs//heads"},
  {0, "refs\\heads"},
  {0, "refs/heads/a.lock"},
  {0, "refs/heads/a.lock/b"},
  {0, "refs/heads/a~1"},
  {0, "refs/heads/a^"},
  {0, "refs/heads/a:b"},
  {0, "refs/heads/a?"},
  {0, "refs/heads/a*"},
  {0, "refs/heads/a[0]"},
  {0, "refs/heads/a\x7f"},
  {0, "refs/heads/a\x01"},
  {0, "refs/heads/a!b"},
  {0, "refs/heads/a\"b"},
  {0, "refs/heads/a#b"},
  {0, "refs/heads/a$b"},
  {0, "refs/heads/a%b"},
  {0, "refs/heads/a&b"},
  {0, "refs/heads/a'b"},
  {1, "refs/heads/a(b"},
  {1, "refs/heads/a)b"},
  {0, "refs/heads/a@{b"},
  {1, "refs/heads/a{b}"},
  {1, "refs/heads/a-b"},
  {1, "refs/heads/a_b"},
  {1, "refs/heads/a+b"},
  {1, "refs/heads/a,b"},
  {1, "refs/heads/a;b"},
  {1, "refs/heads/a<b"},
  {1, "refs/heads/a=b"},
  {1, "refs/heads/a>b"},
  {1, "refs/heads/a|b"},
  {1, "refs/heads/a`b"},
  {1, "refs/heads/a/b/c/d"},
  {0, "refs/heads/."},
  {0, "refs/heads/.."},
  {0, "refs/heads/a..b"},
  {1, "refs/heads/lock"},
  {0, "refs/heads/.lock"},
  {1, "refs/heads/x.lockx"},
};
static const c shas[] = {
  {1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
  {0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {0, "gggggggggggggggggggggggggggggggggggggggg"},
  {1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {0, ""},
  {1, "abababababababababababababababababababab"},
  {1, "0123456789abcdef0123456789abcdef01234567"},
};
int main(void) {
  size_t i;
  for (i = 0; i < sizeof(refs) / sizeof(refs[0]); ++i)
    if (rngit_san_ref(refs[i].text) != refs[i].ok) {
      fprintf(stderr, "san_ref(\"%s\") = %d, reference %d\n", refs[i].text, !refs[i].ok, refs[i].ok);
      return 1;
    }
  for (i = 0; i < sizeof(shas) / sizeof(shas[0]); ++i)
    if (rngit_san_sha(shas[i].text) != shas[i].ok) {
      fprintf(stderr, "san_sha(\"%s\") = %d, reference %d\n", shas[i].text, !shas[i].ok, shas[i].ok);
      return 1;
    }
  return 0;
}
