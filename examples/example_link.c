/* example_link: the reference's Examples/Link.py as a C program.
 *
 *   reticulum-c-example-link --connect HOST:PORT --identity FILE server
 *   reticulum-c-example-link --connect HOST:PORT --identity FILE client DESTINATION
 *
 * The server's destination "example_utilities.linkexample" accepts links. Lines typed on the client are sent
 * over an encrypted link; the server prints each and answers it. "quit" closes the link. A reference Link.py
 * can be either end. The link handling is in example_link.h, the two sides in example_link_chat.h. */
#include "example_link_chat.h"

int main(int argc, char **argv) {
  example_chat_options options = {0};
  options.aspects = "example_utilities.linkexample";
  options.title = "Link example";
  return example_link_main(argc, argv, &options);
}
