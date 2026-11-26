/* Image to WebP conversion for the media pages of reticulum-c-git (included by
 * reticulum_git.c): media.py. The same external encoders are run as
 * subprocesses, in the same preference order, on the output of `git show`:
 *
 *   magick - webp:-       convert - webp:-       gm convert - webp:-
 *   ffmpeg -y -loglevel error -i - -f webp pipe:1   (avconv alike)
 *
 * RNGIT_MEDIA_BACKEND forces one by name, the first one found on PATH is used
 * otherwise and remembered.
 *
 * Repository content is untrusted and image libraries pick a decoder from what
 * they are given, some of which read local files. So, as in RNS 1.6.1
 * (docs/security/2026_11_19): an encoder runs only on content of at most
 * 32 MiB that starts with a PNG, JPEG, GIF, TIFF, WebP or BMP signature, and
 * ImageMagick and GraphicsMagick are told that format (png:-).
 *
 * The conversion has to finish within 8 seconds, the
 * result has to be a WebP file of the size the response can carry, and when no
 * encoder is installed (or one fails) nothing is converted and the caller
 * serves the original, as the reference does. */
#ifndef RETICULUM_C_RNGIT_MEDIA_H
#define RETICULUM_C_RNGIT_MEDIA_H

#define MC_TIMEOUT_MS 8000u
#define MC_INPUT_MAX ((size_t)32 << 20)
typedef struct mc_backend {
  const char *name;
  const char *argv[10];
} mc_backend;
static const mc_backend mc_backends[] = {
    {"magick", {"magick", "-", "webp:-", NULL}},
    {"convert", {"convert", "-", "webp:-", NULL}},
    {"gm", {"gm", "convert", "-", "webp:-", NULL}},
    {"ffmpeg", {"ffmpeg", "-y", "-loglevel", "error", "-i", "-", "-f", "webp", "pipe:1", NULL}},
    {"avconv", {"avconv", "-y", "-loglevel", "error", "-i", "-", "-f", "webp", "pipe:1", NULL}}};
#define MC_BACKEND_COUNT (sizeof(mc_backends) / sizeof(mc_backends[0]))
static int mc_winner = -1;
static int mc_no_backend_logged;

static int mc_which(const char *prog) {
  const char *path = getenv("PATH");
  char dir[PATH_MAX], full[PATH_MAX + 64];
  struct stat st;
  if (!path)
    path = "/usr/local/bin:/usr/bin:/bin";
  while (*path) {
    const char *colon = strchr(path, ':');
    size_t l = colon ? (size_t)(colon - path) : strlen(path);
    if (l && l < sizeof(dir)) {
      memcpy(dir, path, l);
      dir[l] = 0;
      snprintf(full, sizeof(full), "%s/%s", dir, prog);
      if (!stat(full, &st) && S_ISREG(st.st_mode) && !access(full, X_OK))
        return 1;
    }
    if (!colon)
      break;
    path = colon + 1;
  }
  return 0;
}
/* _selected_backend: index into mc_backends or -1 */
static int mc_select(void) {
  const char *forced = getenv("RNGIT_MEDIA_BACKEND");
  size_t i;
  if (forced && *forced) {
    for (i = 0; i < MC_BACKEND_COUNT; ++i)
      if (!strcmp(mc_backends[i].name, forced) && mc_which(mc_backends[i].argv[0]))
        return (int)i;
    return -1;
  }
  if (mc_winner >= 0 && mc_which(mc_backends[mc_winner].argv[0]))
    return mc_winner;
  for (i = 0; i < MC_BACKEND_COUNT; ++i)
    if (mc_which(mc_backends[i].argv[0])) {
      mc_winner = (int)i;
      return (int)i;
    }
  return -1;
}
/* _webp_info: the dimensions in the header of a WebP file */
static int mc_webp_valid(const uint8_t *d, size_t n) {
  unsigned w, h;
  if (n < 30 || memcmp(d, "RIFF", 4) || memcmp(d + 8, "WEBP", 4))
    return 0;
  if (!memcmp(d + 12, "VP8X", 4)) {
    w = ((unsigned)d[24] | (unsigned)d[25] << 8 | (unsigned)d[26] << 16) + 1;
    h = ((unsigned)d[27] | (unsigned)d[28] << 8 | (unsigned)d[29] << 16) + 1;
  } else if (!memcmp(d + 12, "VP8 ", 4)) {
    w = ((unsigned)d[26] | (unsigned)d[27] << 8) & 0x3fffu;
    h = ((unsigned)d[28] | (unsigned)d[29] << 8) & 0x3fffu;
  } else if (!memcmp(d + 12, "VP8L", 4)) {
    unsigned bits = (unsigned)d[21] | (unsigned)d[22] << 8 | (unsigned)d[23] << 16 | (unsigned)d[24] << 24;
    w = (bits & 0x3fffu) + 1;
    h = ((bits >> 14) & 0x3fffu) + 1;
  } else
    return 0;
  return w > 0 && h > 0;
}
/* _classify_image: the format named by the signature, or NULL */
static const char *mc_classify(const uint8_t *d, size_t n) {
  if (n >= 8 && !memcmp(d, "\x89PNG\r\n\x1a\n", 8))
    return "png";
  if (n >= 3 && !memcmp(d, "\xff\xd8\xff", 3))
    return "jpeg";
  if (n >= 6 && (!memcmp(d, "GIF87a", 6) || !memcmp(d, "GIF89a", 6)))
    return "gif";
  if (n >= 4 && (!memcmp(d, "II*\0", 4) || !memcmp(d, "MM\0*", 4)))
    return "tiff";
  if (mc_webp_valid(d, n))
    return "webp";
  if (n >= 18 && !memcmp(d, "BM", 2)) {
    uint32_t dib = (uint32_t)d[14] | (uint32_t)d[15] << 8 | (uint32_t)d[16] << 16 | (uint32_t)d[17] << 24;
    if (dib == 12 || dib == 40 || dib == 52 || dib == 56 || dib == 64 || dib == 108 || dib == 124)
      return "bmp";
  }
  return NULL;
}
/* Runs input_argv in cwd and writes what it prints to the temporary file in.
 * prefix receives the first prefix_cap bytes. False on a timeout, an input
 * over MC_INPUT_MAX or a system error. */
static int mc_collect(char *const *input_argv, const char *cwd, FILE *in, uint64_t t0, uint8_t *prefix, size_t prefix_cap,
                      size_t *prefix_n) {
  int p[2], devnull, ok = 1;
  size_t total = 0;
  pid_t pid;
  *prefix_n = 0;
  if (pipe(p))
    return 0;
  devnull = open("/dev/null", O_RDWR);
  pid = fork();
  if (!pid) {
    if (cwd && chdir(cwd))
      _exit(127);
    dup2(devnull, 0);
    dup2(p[1], 1);
    dup2(devnull, 2);
    close(p[0]);
    close(p[1]);
    execvp(input_argv[0], input_argv);
    _exit(127);
  }
  close(p[1]);
  if (devnull >= 0)
    close(devnull);
  if (pid < 0) {
    close(p[0]);
    return 0;
  }
  for (;;) {
    struct pollfd pf = {p[0], POLLIN, 0};
    uint8_t tmp[8192];
    if (poll(&pf, 1, 20) < 0 && errno != EINTR) {
      ok = 0;
      break;
    }
    if (rngit_idle_hook)
      rngit_idle_hook();
    if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t r = read(p[0], tmp, sizeof(tmp));
      if (r < 0 && errno == EINTR)
        continue;
      if (r <= 0) {
        ok = r == 0;
        break;
      }
      total += (size_t)r;
      if (total > MC_INPUT_MAX || fwrite(tmp, 1, (size_t)r, in) != (size_t)r) {
        ok = 0;
        break;
      }
      if (*prefix_n < prefix_cap) {
        size_t take = prefix_cap - *prefix_n;
        if (take > (size_t)r)
          take = (size_t)r;
        memcpy(prefix + *prefix_n, tmp, take);
        *prefix_n += take;
      }
    }
    if (rngit_monotonic_ms() - t0 > MC_TIMEOUT_MS) {
      ok = 0;
      break;
    }
  }
  close(p[0]);
  if (!ok)
    kill(pid, SIGKILL);
  while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
  }
  return ok;
}
/* convert_to_webp: collects the output of input_argv, run in cwd, runs an
 * encoder on it if it is an image and collects the encoder's output in out
 * (cap bytes). Returns 1 on success. */
static int mc_convert_to_webp(char *const *input_argv, const char *cwd, uint8_t *out, size_t cap, size_t *out_n) {
  int b = mc_select(), q[2], devnull, i;
  pid_t enc_pid;
  size_t got = 0, prefix_n = 0;
  uint64_t t0, status_ok = 0;
  int open_out = 1, killed = 0, status = 0;
  uint8_t prefix[64];
  const char *format, *argv[10];
  char spec[16];
  FILE *in;
  *out_n = 0;
  if (b < 0) {
    if (!mc_no_backend_logged) {
      mc_no_backend_logged = 1;
      log_line("No WebP encoding backend available for media conversion. You can Install ImageMagick or ffmpeg "
               "to enable image conversion.");
    }
    return 0;
  }
  mc_no_backend_logged = 0;
  in = tmpfile();
  if (!in)
    return 0;
  t0 = rngit_monotonic_ms();
  if (!mc_collect(input_argv, cwd, in, t0, prefix, sizeof(prefix), &prefix_n) || fflush(in) || fseek(in, 0, SEEK_SET)) {
    log_line("Media conversion failed: the input could not be read within %u seconds and %zu MiB", MC_TIMEOUT_MS / 1000u,
             MC_INPUT_MAX >> 20);
    fclose(in);
    return 0;
  }
  format = mc_classify(prefix, prefix_n);
  if (!format) {
    log_line("Media conversion failed: Input format is not supported");
    fclose(in);
    return 0;
  }
  memcpy(argv, mc_backends[b].argv, sizeof(argv));
  if (!strcmp(mc_backends[b].name, "magick") || !strcmp(mc_backends[b].name, "convert") || !strcmp(mc_backends[b].name, "gm")) {
    snprintf(spec, sizeof(spec), "%s:-", format);
    for (i = 0; argv[i]; ++i)
      if (!strcmp(argv[i], "-")) {
        argv[i] = spec;
        break;
      }
  }
  if (pipe(q)) {
    fclose(in);
    return 0;
  }
  devnull = open("/dev/null", O_RDWR);
  enc_pid = fork();
  if (!enc_pid) {
    dup2(fileno(in), 0);
    dup2(q[1], 1);
    dup2(devnull, 2);
    close(q[0]);
    close(q[1]);
    execvp(argv[0], (char *const *)argv);
    _exit(127);
  }
  close(q[1]);
  if (devnull >= 0)
    close(devnull);
  fclose(in);
  if (enc_pid < 0) {
    close(q[0]);
    return 0;
  }
  while (open_out) {
    struct pollfd pf = {q[0], POLLIN, 0};
    uint8_t tmp[8192];
    if (poll(&pf, 1, 20) < 0 && errno != EINTR)
      break;
    if (rngit_idle_hook)
      rngit_idle_hook();
    if (pf.revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t r = read(q[0], tmp, sizeof(tmp));
      if (r <= 0)
        open_out = 0;
      else if (got + (size_t)r > cap) {
        killed = 1; /* larger than a response can carry */
        break;
      } else {
        memcpy(out + got, tmp, (size_t)r);
        got += (size_t)r;
      }
    }
    if (rngit_monotonic_ms() - t0 > MC_TIMEOUT_MS) {
      log_line("Media conversion via %s timed out after %u seconds", mc_backends[b].name, MC_TIMEOUT_MS / 1000u);
      killed = 1;
      break;
    }
  }
  close(q[0]);
  if (killed)
    kill(enc_pid, SIGKILL);
  while (waitpid(enc_pid, &status, 0) < 0 && errno == EINTR) {
  }
  status_ok = !killed && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (!status_ok) {
    if (!killed)
      log_line("Media conversion via %s failed.", mc_backends[b].name);
    return 0;
  }
  if (!mc_webp_valid(out, got)) {
    log_line("Media conversion via %s produced invalid WebP output", mc_backends[b].name);
    return 0;
  }
  *out_n = got;
  return 1;
}

#endif
