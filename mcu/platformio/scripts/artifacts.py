# PlatformIO post-build script: collects the flashable files of one environment in
# <build dir>/artifacts/ with the names the release archives use.
#
#   ESP32 / ESP32-S3:  reticulum-c-mcu.bin (the app), bootloader.bin, partitions.bin,
#                      boot_app0.bin, merged.bin (one image for flash address 0x0),
#                      reticulum-c-mcu.elf, flash.txt, size.txt
#   nRF52840:          reticulum-c-mcu.hex, reticulum-c-mcu.uf2 (drag and drop onto the
#                      bootloader drive), reticulum-c-mcu-dfu.zip (serial DFU),
#                      reticulum-c-mcu.elf, flash.txt, size.txt
#
# The flash offsets and flash parameters come from the platform builder itself
# (FLASH_EXTRA_IMAGES, ESP32_APP_OFFSET, the board's flash mode and size), so they are
# whatever `pio run -t upload` would use.
import os
import shutil
import subprocess
import sys

Import("env")  # noqa: F821

NAME = "reticulum-c-mcu"
PLATFORM = env.get("PIOPLATFORM")  # noqa: F821


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def tool(suffix):
    """A binutils tool next to the compiler, for example 'nm' or 'size'."""
    cc = env.subst("$CC")  # noqa: F821
    return cc[: -len("gcc")] + suffix if cc.endswith("gcc") else None


def size_report(elf, out):
    lines = []
    size = tool("size")
    if size:
        lines.append(subprocess.run([size, "-A", "-d", elf], capture_output=True, text=True).stdout)
    out.write("".join(lines))


def esp32(build, art):
    mcu = env.BoardConfig().get("build.mcu")  # noqa: F821
    flash_mode = env.subst("${__get_board_flash_mode(__env__)}")  # noqa: F821
    flash_freq = env.subst("${__get_board_f_image(__env__)}")  # noqa: F821
    flash_size = env.BoardConfig().get("upload.flash_size", "4MB")  # noqa: F821
    app_offset = env.subst("$ESP32_APP_OFFSET")  # noqa: F821
    app = os.path.join(build, "firmware.bin")
    parts = [(off, env.subst(path)) for off, path in env.get("FLASH_EXTRA_IMAGES", [])]  # noqa: F821
    parts.append((app_offset, app))
    esptool = os.path.join(env.PioPlatform().get_package_dir("tool-esptoolpy"), "esptool.py")  # noqa: F821
    merged = os.path.join(art, "merged.bin")
    cmd = [sys.executable, esptool, "--chip", mcu, "merge_bin", "-o", merged,
           "--flash_mode", flash_mode, "--flash_freq", flash_freq, "--flash_size", flash_size]
    for off, path in parts:
        cmd += [off, path]
    run(cmd, stdout=subprocess.DEVNULL)
    names = {}
    for off, path in parts:
        base = os.path.basename(path)
        target = NAME + ".bin" if path == app else base
        shutil.copyfile(path, os.path.join(art, target))
        names[off] = target
    shutil.copyfile(os.path.join(build, "firmware.elf"), os.path.join(art, NAME + ".elf"))
    chip = mcu
    args = " ".join("%s %s" % (off, names[off]) for off, _ in parts)
    with open(os.path.join(art, "flash.txt"), "w") as f:
        f.write(
            "Flash the single merged image (all parts, written at address 0x0):\n\n"
            "  python3 -m esptool --chip %s -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin\n\n"
            "Or flash the parts separately (same result):\n\n"
            "  python3 -m esptool --chip %s -p /dev/ttyUSB0 -b 460800 write_flash \\\n"
            "    --flash_mode %s --flash_freq %s --flash_size %s %s\n\n"
            "Replace /dev/ttyUSB0 with the board's port (/dev/ttyACM0 on a native USB port, COMx on\n"
            "Windows). If the board does not enter the bootloader by itself, hold BOOT, tap RESET,\n"
            "release BOOT. Install esptool with: pip install esptool\n"
            % (chip, chip, flash_mode, flash_freq, flash_size, args))


def nrf52(build, art):
    hexfile = os.path.join(build, "firmware.hex")
    shutil.copyfile(hexfile, os.path.join(art, NAME + ".hex"))
    shutil.copyfile(os.path.join(build, "firmware.elf"), os.path.join(art, NAME + ".elf"))
    zipfile = os.path.join(build, "firmware.zip")
    if os.path.exists(zipfile):
        shutil.copyfile(zipfile, os.path.join(art, NAME + "-dfu.zip"))
    framework = env.PioPlatform().get_package_dir("framework-arduinoadafruitnrf52")  # noqa: F821
    uf2conv = os.path.join(framework, "tools", "uf2conv", "uf2conv.py")
    run([sys.executable, uf2conv, hexfile, "-c", "-f", "0xADA52840",
         "-o", os.path.join(art, NAME + ".uf2")], stdout=subprocess.DEVNULL)
    with open(os.path.join(art, "flash.txt"), "w") as f:
        f.write(
            "Put the board into the bootloader: double-tap RESET (a drive named after the board, for\n"
            "example RAK4631, HT-n5262 or TECHOBOOT, appears and the LED pulses).\n\n"
            "Drag and drop (any OS):\n\n"
            "  copy %s.uf2 onto that drive; the board reboots into the firmware.\n\n"
            "Or over the serial DFU port (pip install adafruit-nrfutil):\n\n"
            "  adafruit-nrfutil --verbose dfu serial --package %s-dfu.zip -p /dev/ttyACM0 -b 115200 --singlebank\n\n"
            "The firmware is a USB serial device (CDC); the HDLC stream of the Reticulum\n"
            "SerialInterface runs on it. The host must assert DTR (any normal serial open does).\n"
            % (NAME, NAME))


def collect(source, target, env):  # noqa: F811
    build = env.subst("$BUILD_DIR")
    art = os.path.join(build, "artifacts")
    if os.path.isdir(art):
        shutil.rmtree(art)
    os.makedirs(art)
    if PLATFORM == "espressif32":
        esp32(build, art)
    elif PLATFORM == "nordicnrf52":
        nrf52(build, art)
    elf = os.path.join(build, "firmware.elf")
    with open(os.path.join(art, "size.txt"), "w") as out:
        size_report(elf, out)
        if PLATFORM == "nordicnrf52":
            nm = tool("nm")
            symbols = {}
            for line in subprocess.run([nm, elf], capture_output=True, text=True).stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[2] in ("__HeapBase", "__HeapLimit"):
                    symbols[parts[2]] = int(parts[0], 16)
            if len(symbols) == 2:
                out.write("\nnRF52840 heap (RAM left for malloc after .data/.bss, before the 2 KB main stack): "
                          "%d bytes\n" % (symbols["__HeapLimit"] - symbols["__HeapBase"]))


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin" if PLATFORM == "espressif32" else "$BUILD_DIR/${PROGNAME}.zip",  # noqa: F821
                  collect)
