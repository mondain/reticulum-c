/* White-box checks of host helpers that cannot be observed through a PTY: the
 * Linux pty driver forces 8N1 on both ends, so termios flags are verified
 * directly. */
#include "../src/host_posix.c"

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, #x);                   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static void serial_frame_flags(void) {
  static const struct {
    unsigned bits, stop;
    char parity;
    tcflag_t size;
    int parenb, parodd, cstopb;
  } cases[] = {{0, 0, 0, CS8, 0, 0, 0},   {7, 1, 'E', CS7, 1, 0, 0},
               {8, 2, 'O', CS8, 1, 1, 1}, {5, 1, 'N', CS5, 0, 0, 0},
               {6, 0, 'E', CS6, 1, 0, 0}};
  unsigned k;
  for (k = 0; k < sizeof(cases) / sizeof(*cases); ++k) {
    rnc_host_config c = {0};
    struct termios t;
    memset(&t, 0, sizeof(t));
    t.c_cflag = CS8 | PARENB | PARODD | CSTOPB; /* stale bits must be cleared */
    c.serial_databits = cases[k].bits;
    c.serial_stopbits = cases[k].stop;
    c.serial_parity = cases[k].parity;
    serial_flags(&c, &t);
    CHECK((t.c_cflag & CSIZE) == cases[k].size);
    CHECK(!!(t.c_cflag & PARENB) == cases[k].parenb);
    CHECK(!!(t.c_cflag & PARODD) == cases[k].parodd);
    CHECK(!!(t.c_cflag & CSTOPB) == cases[k].cstopb);
    CHECK((t.c_cflag & (CLOCAL | CREAD)) == (CLOCAL | CREAD));
  }
}
int main(void) {
  serial_frame_flags();
  puts("host internal tests passed");
  return 0;
}
