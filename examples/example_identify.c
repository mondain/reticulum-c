/* example_identify: the reference's Examples/Identify.py as a C program, with an allow list.
 *
 *   reticulum-c-example-identify --connect HOST:PORT --identity FILE [--allow IDENTITY]... server
 *   reticulum-c-example-identify --connect HOST:PORT --identity FILE client DESTINATION
 *
 * A link does not tell the server who opened it. The client here identifies itself over the established link
 * with the identity in its --identity file (the reference example makes a new one each run), which only the
 * server can see. The server of "example_utilities.identifyexample" reports who it is and names them in its
 * answers. With --allow (an identity hash, repeatable; an addition to the reference example) it closes the
 * link of anyone else and reads nothing from a peer that has not identified. */
#include "example_link_chat.h"

int main(int argc, char **argv) {
  example_chat_options options = {0};
  options.aspects = "example_utilities.identifyexample";
  options.title = "Link identification example";
  options.identify = 1;
  return example_link_main(argc, argv, &options);
}
