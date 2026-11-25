"""Loaded by the oracle processes of the interoperability workflow (RNC_INTEROP_PYTHONPATH).

RNS 1.6 searches a proof of work for every announce and path request it emits, at a default value of 25 and 15.8.
On a small CI runner that takes longer than many scenarios wait for a reference peer to announce, so those peers
stamp cheaply here. Only what the oracle emits changes: the costs it requires of others, and every [stamps] option a
test writes into its own configuration, are untouched (a config is read after this runs and wins).
"""
import builtins
import sys

_import = builtins.__import__
_done = False


def _patched(name, *args, **kwargs):
    global _done
    module = _import(name, *args, **kwargs)
    if not _done:
        transport = sys.modules.get("RNS.Transport")
        cls = getattr(transport, "Transport", None) if transport is not None else None
        if cls is not None and hasattr(cls, "DESTINATION_VALUE") and hasattr(cls, "PR_VALUE"):
            cls.DESTINATION_VALUE = 8.0
            cls.PR_VALUE = 8.0
            _done = True
    return module


builtins.__import__ = _patched
