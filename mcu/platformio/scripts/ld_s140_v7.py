# PlatformIO pre-build script: makes the project's ld/ directory visible to the linker, for
# boards whose JSON names a linker script the nordicnrf52 framework does not ship
# (nrf52840_s140_v7.ld, for bootloaders that carry the S140 7.3.0 SoftDevice).
import os

Import("env")  # noqa: F821

env.Append(LIBPATH=[os.path.join(env.subst("$PROJECT_DIR"), "ld")])  # noqa: F821
