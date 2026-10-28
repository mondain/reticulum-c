# PlatformIO library extra script for reticulum-c (referenced by library.json).
#
# Adds what library.json flags cannot express (paths relative to the library root)
# and the values the build must supply to the portable application:
#   RNC_MCU_VERSION      the project version, read from CMakeLists.txt (single source)
#   RNC_MCU_BUILD_EPOCH  seconds since 1970: $RNC_MCU_BUILD_EPOCH, else
#                        $SOURCE_DATE_EPOCH, else now (see rnc_mcu_app.h, clock policy)
# Include paths and the capacity profile are also given to the project's own sources,
# because the profile constants size public structs (rnc_packet, rnc_node_event, ...):
# the library and every file that includes reticulum_c headers must agree.
# Optional: $RNC_PROFILE_HEADER names a profile header file (absolute path) that is
# used instead of include/reticulum_c/rnc_profile_mcu.h, for library and project.
import os
import re
import time

Import("env")  # noqa: F821  (provided by SCons)

try:
    here = os.path.dirname(os.path.abspath(__file__))
except NameError:  # SCons does not always define __file__
    here = os.path.join(Dir(".").srcnode().abspath)  # noqa: F821
root = os.path.abspath(os.path.join(here, "..", ".."))

version = "0.0.0"
# CMakeLists.txt is the single source; library.json is the fallback when a library
# archive without it is used (.github/scripts/check-version.sh keeps them equal)
for name, pattern in (("CMakeLists.txt", r"^project\(reticulum_c VERSION ([0-9][0-9.]*)"),
                      ("library.json", r'^\s*"version"\s*:\s*"([0-9][0-9.]*)"')):
    path = os.path.join(root, name)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            m = re.search(pattern, f.read(), re.M)
        if m:
            version = m.group(1)
            break
epoch = os.environ.get("RNC_MCU_BUILD_EPOCH") or os.environ.get("SOURCE_DATE_EPOCH") or str(int(time.time()))

defines = [
    ("RNC_MCU_VERSION", env.StringifyMacro(version)),
    ("RNC_MCU_BUILD_EPOCH", epoch + "u"),
]
if os.environ.get("RNC_PROFILE_HEADER"):
    defines.append(("RNC_PROFILE_HEADER", env.StringifyMacro(os.environ["RNC_PROFILE_HEADER"])))
paths = [
    os.path.join(root, "include"),
    os.path.join(root, "src"),
    os.path.join(root, "src", "third_party", "monocypher"),
    os.path.join(root, "mcu", "app"),
    os.path.join(root, "mcu", "radio"),
]
# the library itself
env.Append(CPPPATH=paths, CPPDEFINES=defines)
# the project (the sketch includes rnc_mcu_app.h and the reticulum_c headers)
global_env = DefaultEnvironment()  # noqa: F821
global_env.Append(CPPPATH=[paths[0], paths[3], paths[4]],
                  CPPDEFINES=[("RNC_PROFILE_MCU", 1)] + defines)
