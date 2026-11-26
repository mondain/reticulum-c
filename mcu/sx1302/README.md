# SX1302 concentrator as an RNode (WM1302 Pi HAT)

STATUS: untested on hardware. Built and checked only against a libloragw test double
(`tests/`) and end to end with `reticulum-c-node` driving it over a pty through that
double. No frame has gone over the air yet.

`reticulum-c-rnode-sx1302` makes an SX1302/SX1250 concentrator (Seeed WM1302 SPI module on
the WM1302 Pi HAT, tested target: Raspberry Pi 3 Model B) act as an RNode on a pseudo
terminal. Any RNode host drives it: `reticulum-c-node` with `type = RNodeInterface`, or the
reference `rnsd`. It reuses the portable radio core unchanged (`mcu/radio`: air framing and
split packets, CSMA, airtime budget, the RNode device protocol). Only the chip driver is new:
`rnc_sx1302.c`, an `rnc_modem` on Semtech's libloragw.

```text
reticulum-c-node / rnsd --RNode KISS--> pty --> rnc_rnode --> rnc_lora_if --> rnc_sx1302 --> libloragw --> SX1302
```

## How the concentrator is used

As a single-channel radio, like an RNode: RF chain 0 is centred on the frequency and only the
"LoRa service" IF chain (IF 8) is on, at the exact bandwidth and SF the host sets. It is the
only SX1302 demodulator that takes 125, 250 and 500 kHz at a fixed SF. The eight multi-SF
demodulators (125 kHz only) stay off, so no frame is received twice. Private sync word
(`lorawan_public = false`, 0x12), explicit header, CRC on, standard IQ.

Limits, all from the chip or libloragw:

- Bandwidths 125, 250 and 500 kHz only (an RNode setting of 62.5 kHz or less is refused).
- No carrier sense: libloragw does not show preamble detection, so CSMA is a random backoff
  without listening. The SX1261 on the module could add LBT later.
- Half duplex: frames that arrive while it transmits are lost.
- `lgw_start()` takes one to three seconds and blocks. Changing the frequency, bandwidth, SF
  or power restarts the concentrator; changing the coding rate or preamble does not. Start it
  at launch with the host's setting (`--freq --bw --sf --txp`) so the host is answered at once.
- Power: 12 to 27 dBm from the WM1302 US915 calibrated gain table. Below 12 dBm the power
  index is an uncalibrated estimate (a warning is printed), so measure it before you rely on it.

## Build

```sh
sudo raspi-config   # Interface Options: enable SPI and I2C (lgw_start reads the I2C temperature sensor), reboot
git clone https://github.com/Lora-net/sx1302_hal ~/sx1302_hal && make -C ~/sx1302_hal
cmake -S . -B build -DRNC_SX1302_HAL=$HOME/sx1302_hal
cmake --build build --target reticulum-c-rnode-sx1302
```

## Run

Attach the LoRa antenna before power is applied.

```sh
sudo build/reticulum-c-rnode-sx1302 --link /run/rnode-sx1302 \
     --freq 915000000 --bw 125000 --sf 8 --cr 5 --txp 17 -v
```

Then in the node's configuration:

```ini
  [[WM1302]]
    type = RNodeInterface
    port = /run/rnode-sx1302
    frequency = 915000000
    bandwidth = 125000
    txpower = 17
    spreadingfactor = 8
    codingrate = 5
```

The program drives the HAT's reset and power lines itself through the GPIO character device,
by line offset: reset 17, power enable 18, SX1261 reset 5 (`--reset --power --sx1261-reset`).
Line offsets work on every kernel. The sysfs numbers in some guides (588/589/576) depend on the
kernel's GPIO base. If you would rather run `reset_lgw.sh`, use `--no-reset`.

Nothing is transmitted until the host has set every radio setting and turned the radio on.
The airtime budget defaults to 1 % per hour (`--airtime`). Frequency, power and duty cycle are
the operator's responsibility; nothing here checks them against a regional plan.

## Not established

- On-air exchange with an SX126x/SX127x RNode (reticulum-c firmware or stock).
- That the service channel receives SF5/SF6 from an SX126x peer.
- RSSI and SNR calibration (the WM1302 offsets −215.4 dB plus temperature compensation are used).
- Whether IF 0 (the default) is the best place for the channel; `--if-offset` moves it.
