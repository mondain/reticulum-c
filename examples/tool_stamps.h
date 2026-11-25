/* Network stamps (RNS 1.6) for the listening command line tools, with the reference's defaults: announces at
 * value 25, path requests at 15.8. The announce stamp is searched in the background, kept in
 * <identity file>.stamps, and the first announce waits for it. `--stamp-value N` (default: the environment's
 * RNC_STAMP_VALUE, else 25) sets the value; 0 turns announce and path request stamping off. Link request
 * stamps are separate (rnc_host_set_link_stamping). Initiators only need tool_stamps_requests. */
#ifndef RNC_EXAMPLES_TOOL_STAMPS_H
#define RNC_EXAMPLES_TOOL_STAMPS_H
#include "node_stamper.h"
#include "tool_stamp_value.h"
static int tool_stamps_said_generating, tool_stamps_said_ready;
/* For a listener, after its destinations are registered. */
static inline void tool_stamps_listen(rnc_node *node, const char *identity_path, double value) {
  stamper_options o;
  if (value <= 0)
    return;
  memset(&o, 0, sizeof(o));
  o.stamp_destinations = o.stamp_prs = 1;
  o.destination_value = value;
  o.pr_value = PR_STAMP_VALUE;
  o.pr_stamp_timeout = PR_STAMP_TIMEOUT;
  stamper_start_options(&o, node, identity_path);
}
/* 1 once every local destination has its stamp (or none will be had): announcing can start. */
static inline int tool_stamps_ready(void) {
  uint8_t destination[16];
  size_t i;
  if (!stp.enabled || !stp.node)
    return 1;
  for (i = 0; rnc_node_destination_at(stp.node, i, destination) == RNC_OK; ++i)
    if (!stamper_has(destination))
      return 0;
  return 1;
}
/* Once per turn of the listener's loop. */
static inline void tool_stamps_step(void) {
  if (!stp.enabled || !stp.node)
    return;
  stamper_step();
  if (stp.searching && !tool_stamps_said_generating) {
    tool_stamps_said_generating = 1;
    fprintf(stderr, "Generating announce stamp of value %.2f, announcing once it is found\n", stp.value);
  }
  if (!tool_stamps_said_ready && tool_stamps_ready()) {
    tool_stamps_said_ready = 1;
    if (stp.gave_up_count)
      fprintf(stderr, "Could not generate an announce stamp; announcing without one\n");
    else
      fprintf(stderr, "Announce stamp ready\n");
  }
}
static inline void tool_stamps_stop(void) {
  stamper_stop();
}
#endif
