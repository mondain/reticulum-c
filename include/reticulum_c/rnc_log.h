#ifndef RETICULUM_C_LOG_H
#define RETICULUM_C_LOG_H
#ifdef __cplusplus
extern "C" {
#endif
/* Process-wide logging hook. The library is silent until a handler is set;
 * levels and their meaning follow RNS (RNS.LOG_*). Set the handler and level
 * before using the library from several threads; the handler itself must be
 * safe to call from whichever thread logs. */
#define RNC_LOG_NONE (-1)
#define RNC_LOG_CRITICAL 0
#define RNC_LOG_ERROR 1
#define RNC_LOG_WARNING 2
#define RNC_LOG_NOTICE 3
#define RNC_LOG_INFO 4
#define RNC_LOG_VERBOSE 5
#define RNC_LOG_DEBUG 6
#define RNC_LOG_PATHING 7
#define RNC_LOG_EXTREME 8
#define RNC_LOG_MESSAGE_MAX 512

/* `module` names the part of the SDK ("node", "link", "host", ...). The message
 * is NUL-terminated, without a trailing newline, and only valid during the call. */
typedef void (*rnc_log_handler)(void *context, int level, const char *module,
                                const char *message);
/* NULL removes the handler. */
void rnc_log_set_handler(rnc_log_handler handler, void *context);
/* Messages above this level are dropped; default RNC_LOG_NOTICE. Out-of-range
 * values clamp to RNC_LOG_NONE..RNC_LOG_EXTREME. */
void rnc_log_set_level(int level);
int rnc_log_level(void);
/* 1 when a message at `level` would be delivered. */
int rnc_log_enabled(int level);
/* printf-style; messages longer than RNC_LOG_MESSAGE_MAX are truncated. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
void rnc_logf(int level, const char *module, const char *format, ...);
/* "[Notice]  " style label as RNS prints it; "Unknown" for other values. */
const char *rnc_log_level_name(int level);
#ifdef __cplusplus
}
#endif
#endif
