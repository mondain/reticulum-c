#include <reticulum_c/rnc_log.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static rnc_log_handler handler;
static void *handler_context;
static int level = RNC_LOG_NOTICE;
void rnc_log_set_handler(rnc_log_handler h, void *context) {
  handler = h;
  handler_context = context;
}
void rnc_log_set_level(int l) {
  if (l < RNC_LOG_NONE)
    l = RNC_LOG_NONE;
  if (l > RNC_LOG_EXTREME)
    l = RNC_LOG_EXTREME;
  level = l;
}
int rnc_log_level(void) { return level; }
int rnc_log_enabled(int l) {
  return handler && level != RNC_LOG_NONE && l <= level;
}
void rnc_logf(int l, const char *module, const char *format, ...) {
  char message[RNC_LOG_MESSAGE_MAX];
  va_list args;
  if (!rnc_log_enabled(l) || !format)
    return;
  va_start(args, format);
  (void)vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  handler(handler_context, l, module ? module : "", message);
}
const char *rnc_log_level_name(int l) {
  switch (l) {
  case RNC_LOG_CRITICAL:
    return "[Critical]";
  case RNC_LOG_ERROR:
    return "[Error]   ";
  case RNC_LOG_WARNING:
    return "[Warning] ";
  case RNC_LOG_NOTICE:
    return "[Notice]  ";
  case RNC_LOG_INFO:
    return "[Info]    ";
  case RNC_LOG_VERBOSE:
    return "[Verbose] ";
  case RNC_LOG_DEBUG:
    return "[Debug]   ";
  case RNC_LOG_PATHING:
    return "[Pathing] ";
  case RNC_LOG_EXTREME:
    return "[Extra]   ";
  default:
    return "Unknown";
  }
}
