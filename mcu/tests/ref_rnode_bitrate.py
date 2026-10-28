#!/usr/bin/env python3
"""Prints the on-air bit rate the unmodified reference RNodeInterface computes for every
spreading factor, bandwidth and coding rate the firmware accepts:

    ref_rnode_bitrate.py            lines "SF BW CR BITRATE" (BITRATE as a float)

The reference's own updateBitrate() is called (on an object made without opening a
serial port); nothing is reimplemented. PYTHONPATH must contain the reference checkout.
"""
import sys

try:
    from RNS.Interfaces.RNodeInterface import RNodeInterface
except Exception as e:  # missing checkout or its dependencies
    sys.stderr.write("cannot import the reference RNodeInterface: %s\n" % e)
    sys.exit(77)

BANDWIDTHS = [7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000]
for sf in range(5, 13):
    for bw in BANDWIDTHS:
        for cr in range(5, 9):
            iface = RNodeInterface.__new__(RNodeInterface)
            iface.r_sf, iface.r_cr, iface.r_bandwidth = sf, cr, bw
            iface.updateBitrate()
            print("%d %d %d %.9f" % (sf, bw, cr, iface.bitrate))
