#!/usr/bin/env python3
"""Drives the unmodified reference Reticulum (RNS 1.5.5) with an RNodeInterface on the
given serial port and announces one destination, then waits.

    ref_rnode_driver.py PORT SECONDS

Exit 77 when the reference or its serial module is not available, 1 when the interface
did not come online, 0 otherwise. The caller checks what the radio side heard.
PYTHONPATH must contain the reference checkout."""
import os
import sys
import tempfile
import time

try:
    import serial  # noqa: F401  (pyserial: the reference opens the port with it)
    import RNS
except Exception as e:
    sys.stderr.write("cannot import the reference or pyserial: %s\n" % e)
    sys.exit(77)

port, seconds = sys.argv[1], float(sys.argv[2])
config = tempfile.mkdtemp(prefix="rnc-ref-rnode-")
with open(os.path.join(config, "config"), "w") as f:
    f.write("""[reticulum]
  enable_transport = No
  share_instance = No
[interfaces]
  [[RNode]]
    type = RNodeInterface
    enabled = yes
    port = %s
    frequency = 915000000
    bandwidth = 125000
    txpower = 10
    spreadingfactor = 8
    codingrate = 5
""" % port)
reticulum = RNS.Reticulum(configdir=config, loglevel=RNS.LOG_VERBOSE)
online = False
deadline = time.time() + 30
while time.time() < deadline and not online:
    online = any(getattr(i, "online", False) for i in RNS.Transport.interfaces if type(i).__name__ == "RNodeInterface")
    time.sleep(0.5)
if not online:
    sys.stderr.write("the reference RNodeInterface did not come online\n")
    sys.exit(1)
identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "reticulum_c", "rnode", "interop")
destination.announce()
time.sleep(seconds)
sys.exit(0)
