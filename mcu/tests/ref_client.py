"""Reference RNS client for the MCU example firmware test (mcu/tests/mcu_host.sh).

  ref_client.py RNS_CONFIG_DIR TIMEOUT_SECONDS

Waits for the announce of reticulum_c.mcu.example, requests /echo and checks
that the reply equals the request. Needs the unmodified reference RNS on
PYTHONPATH. Exits 0 on success."""
import sys
import time

import RNS


class Handler:
    aspect_filter = "reticulum_c.mcu.example"

    def __init__(self):
        self.destination_hash = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        self.destination_hash = destination_hash


def main():
    config, timeout = sys.argv[1], float(sys.argv[2])
    RNS.Reticulum(configdir=config, loglevel=RNS.LOG_WARNING)
    handler = Handler()
    RNS.Transport.register_announce_handler(handler)
    deadline = time.time() + timeout
    while handler.destination_hash is None and time.time() < deadline:
        time.sleep(0.2)
    if handler.destination_hash is None:
        print("ref_client: no announce from the MCU destination", file=sys.stderr)
        return 1
    identity = RNS.Identity.recall(handler.destination_hash)
    destination = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                                  "reticulum_c", "mcu", "example")
    link = RNS.Link(destination)
    while link.status != RNS.Link.ACTIVE and time.time() < deadline:
        if link.status == RNS.Link.CLOSED:
            link = RNS.Link(destination)
        time.sleep(0.2)
    if link.status != RNS.Link.ACTIVE:
        print("ref_client: link did not become active", file=sys.stderr)
        return 1
    payload = [1, "mcu", b"\x00\xff"]
    result = {}

    def ok(receipt):
        result["data"] = receipt.response

    def failed(receipt):
        result["failed"] = True

    link.request("/echo", data=payload, response_callback=ok, failed_callback=failed, timeout=20)
    while not result and time.time() < deadline:
        time.sleep(0.1)
    if result.get("data") != payload:
        print("ref_client: /echo mismatch: %r" % (result,), file=sys.stderr)
        return 1
    print("reference /echo ok")
    info = {}

    def got_info(receipt):
        info["data"] = receipt.response

    link.request("/info", data=None, response_callback=got_info, failed_callback=failed, timeout=20)
    result.clear()
    while "data" not in info and not result and time.time() < deadline:
        time.sleep(0.1)
    data = info.get("data")
    if not isinstance(data, dict) or data.get("name") != "reticulum-c-mcu":
        print("ref_client: /info mismatch: %r" % (data,), file=sys.stderr)
        return 1
    print("reference /info ok: %r" % (data,))
    return 0


sys.exit(main())
