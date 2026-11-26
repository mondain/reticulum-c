#!/usr/bin/env python3
"""Prints what the unmodified reference RNS.Stamps computes, one record per line, for
tests/test_netstamp_reference.c to compare with this library:

    C cost fp bytes_hex quantized     cost_to_fp, cost_to_bytes, quantize_cost
    V material_hex stamp_hex cost valid value     stamp_valid and stamp_value on the unexpanded workblock
    E stamp_hex link_cost ext_hex     the announce extension Destination._announce builds
    I private_hex public_hex value    RNS.Identity(value=8) and a plain RNS.Identity, with get_value()
    J private_hex public_hex value    the stamped identity given as argument, as the reference reads it

PYTHONPATH must contain the reference checkout. Nothing here is reimplemented: every number comes from
RNS.Stamps and RNS.Identity.
"""
import hashlib
import sys

try:
    import RNS
    from RNS import Stamps
except Exception as e:  # missing checkout or its dependencies
    sys.stderr.write("cannot import the reference RNS: %s\n" % e)
    sys.exit(77)

COSTS = [0, 0.001, 0.5, 1, 8, 9.5, 12.5, 15.8, 15.84, 15.84375, 23.5, 25, 40, 99.99, 100, 100.5, 250, -1]
for c in COSTS:
    fp = Stamps.cost_to_fp(c)
    print("C %r %d %s %r" % (c, fp, Stamps.cost_to_bytes(c).hex(), Stamps.quantize_cost(c)))

MATERIALS = [b"", b"\x01\x02\x03\x04", bytes(range(90)), hashlib.sha256(b"reticulum-c").digest() * 3]


def stamp_stream(material, count):
    for i in range(count):
        yield hashlib.sha256(material + i.to_bytes(4, "big")).digest()[:14]


for material in MATERIALS:
    wb = Stamps.stamp_workblock(material, expand_rounds=0)
    for stamp in stamp_stream(material, 60):
        value = Stamps.stamp_value(wb, stamp)
        grid = 1 / 256
        costs = {0, 1, 5.5, 12, 23.5, 25, value, value + grid, value - grid, value + 1}
        for cost in sorted(c for c in costs if 0 <= c <= 100):
            valid = Stamps.stamp_valid(stamp, cost, wb)
            print("V %s %s %r %d %r" % (material.hex() or "-", stamp.hex(), cost, 1 if valid else 0, value))
        flipped = bytearray(stamp)
        flipped[3] ^= 0x10
        flipped = bytes(flipped)
        fv = Stamps.stamp_value(wb, flipped)
        print("V %s %s %r %d %r" % (material.hex() or "-", flipped.hex(), 12.0, 1 if Stamps.stamp_valid(flipped, 12.0, wb) else 0, fv))

for link_cost in (0, 12.5, 40, 100):
    stamp = hashlib.sha256(b"ext").digest()[:14]
    cb = Stamps.cost_to_bytes(link_cost)
    ext = bytes([RNS.Identity.EXTPAYLOADMARKER, 0x00]) + stamp + bytes([cb[1], cb[0]])
    print("E %s %r %s" % (stamp.hex(), link_cost, ext.hex()))

for identity in [RNS.Identity(value=8) for _ in range(3)] + [RNS.Identity()]:
    print("I %s %s %r" % (identity.get_private_key().hex(), identity.get_public_key().hex(), identity.get_value()))

theirs = RNS.Identity(create_keys=False)
theirs.load_private_key(bytes.fromhex(sys.argv[1]))
print("J %s %s %r" % (sys.argv[1], theirs.get_public_key().hex(), theirs.get_value()))
