/* The tools' --stamp-value, and path request stamping for the node of a tool. */
#ifndef RNC_EXAMPLES_TOOL_STAMP_VALUE_H
#define RNC_EXAMPLES_TOOL_STAMP_VALUE_H
#include "pr_stamp.h"
#include <stdlib.h>
#define TOOL_STAMP_VALUE 25.0
static inline int tool_stamp_parse(const char *text, double *value) {
  char *end;
  double v;
  if (!text || !*text)
    return 0;
  v = strtod(text, &end);
  if (*end || !(v >= 0 && v <= 100))
    return 0;
  *value = v;
  return 1;
}
static inline double tool_stamp_default(void) {
  double value = TOOL_STAMP_VALUE;
  (void)tool_stamp_parse(getenv("RNC_STAMP_VALUE"), &value);
  return value;
}
static inline void tool_stamps_requests(rnc_node *node, double value) {
  if (value > 0)
    (void)rnc_node_set_stamp_provider(node, pr_stamp_default_provider, NULL);
}
#endif
