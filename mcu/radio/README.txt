LoRa radio support for the reticulum-c microcontroller firmware
================================================================

STATUS: written and tested on the host only. NOTHING HERE HAS EVER RUN ON A RADIO. The
drivers were checked against software models of the chips that were written by the same
author from the same datasheets, so a misreading of a datasheet would be in both. The over
the air format was derived from the published RNode firmware (see "Provenance and
licence") and has never been exchanged with a real RNode. Treat every claim of
compatibility below as "derived and simulated", not "verified".

What is here
------------
Portable C (C11), no platform headers, no dependency on the protocol core:

  rnc_radio_hal.h   the hardware interface: SPI transfer, GPIO write/read, microsecond delay
                    and clock. Polling based; the interrupt line is only a hint.
  rnc_lora_phy.*    LoRa arithmetic: bandwidth table, symbol time, low data rate rule,
                    preamble length, time on air (Semtech formula, integer microseconds,
                    rounded up), the RNode style bit rate.
  rnc_lora_air.*    the over-the-air framing: header byte, split of packets above 254 bytes
                    into two frames, reassembly with sequence matching, orphan timeout,
                    duplicate suppression.
  rnc_lora_mac.*    the airtime budget (percent of every hour, enforced before every
                    transmission) and a CSMA style listen-before-talk with random backoff.
  rnc_modem.h       the interface the two drivers implement.
  rnc_sx126x.*      SX1261 / SX1262 / SX1268 driver.
  rnc_sx127x.*      SX1276 / SX1277 / SX1278 / SX1279 driver.
  rnc_lora_if.*     the interface adapter: a radio plus framing, CSMA and budget, exchanging
                    whole Reticulum packets (MTU 500) with the application.
  rnc_lora_cfg.h    the radio settings (lora.mode, .freq, .bw, .sf, .cr, .txp, .airtime):
                    parsing, validation, printing.
  rnc_boards.*      the board table: chip variant, pins, TCXO, antenna switch, PMU.
  rnc_radio.*       the one place that decides whether the radio may run (see "Regulatory").

Ports (not portable code): mcu/esp-idf/example/main/radio_hal_idf.c (ESP-IDF spi_master,
gpio, esp_timer), mcu/platformio/src/radio_hal.cpp (Arduino SPI library, ESP32 and nRF52),
mcu/platformio/variants/rnc_nrf52840 (an identity pin map so that chip GPIO numbers can be
used on the nRF52 boards).

REGULATORY SAFETY
-----------------
The radio is OFF until the operator has set, explicitly, the mode (lora.mode leaf or
gateway) AND the frequency, bandwidth, spreading factor, coding rate and transmit power.
Until then the chip is not spoken to at all: no SPI traffic, no transmission, no
reception. There are no default transmit settings anywhere: not in the sources, not in
Kconfig, not in sdkconfig defaults, not in platformio.ini, not in the release images (a
test, mcu/tests/mcu_radio.sh, fails if one appears). The only default is the airtime
budget: 1 percent of every hour, chosen to be low.

THE OPERATOR IS RESPONSIBLE for using a frequency, a power and a duty cycle that are legal
where the board is operated, for the antenna and cable (the power setting is the power at
the chip's output, not at the antenna), and for any licence or certification that applies.
The airtime budget is a safety net, not a compliance proof: it counts this node's own
transmissions only, in the time on air computed from the settings, and does not know your
regulator's rules (sub-bands, listen-before-talk requirements, per-band limits).
The firmware does not check the frequency against any regional plan.

Provenance and licence
----------------------
The RNode firmware (https://github.com/markqvist/RNode_Firmware, GPL-3.0) was cloned into a
scratch directory outside this repository and READ to establish FACTS about the on-air
format, modem settings and boards: byte layouts, constants, register values, pin numbers,
chip variants. No code and no comments were copied, translated or paraphrased from it; the
code in this directory was written independently from those facts and from the public
Semtech datasheets (SX1261/2 and SX1276/77/78/79 data sheets, AN1200.13 formulas). Where a
fact could not be established from the source, the section "Not established" says so.
This directory is covered by the repository's MIT licence. The facts, listed below, are
not copyrightable expression; the RNode firmware keeps its own licence. See PROVENANCE.md.

The over-the-air format
-----------------------
Established from the RNode firmware (facts only):

 1. Every LoRa frame starts with one header byte. Bits 7..4 are a sequence number (a random
    nibble per packet), bits 3..1 are zero when sent, bit 0 is the "split" flag.
 2. A frame holds at most 255 bytes (the LoRa payload limit): the header plus 254 packet
    bytes. A packet of up to 254 bytes is sent in one frame with the split flag clear.
    A larger packet, up to the RNode's MTU of 508 bytes, is sent as two frames with the
    same header byte (split flag set): the first with exactly 254 packet bytes, the second
    with the rest. Reticulum's own MTU is 500, so the second frame carries at most 246.
 3. Reception: one packet is kept pending and one sequence value ("unset" = 0xFF). A frame
    without the split flag is a whole packet and discards a pending half. A split frame
    starts a new pending packet when none is pending or when its sequence number differs
    from the pending one (the old half is lost); with the same sequence number it is the
    second half and completes the packet. There is no timeout and no length check.
 4. Radio settings the firmware applies: explicit header, CRC on, standard (non inverted)
    IQ, private network sync word (SX127x: 0x12; SX126x: 0x1424 in registers 0x0740/0x0741),
    coding rate given as the denominator 5..8, bandwidths from 7.8 to 500 kHz, spreading
    factor 5..12 (SX126x) or 6..12 (SX127x; SF6 needs implicit headers).
 5. Preamble: the firmware targets 24 ms (6 ms for rates above 30 kbit/s) with a floor of
    18 symbols. On the SX127x it writes the symbol count minus 4 to the preamble register.
 6. The low data rate optimisation is switched on when the integer expression
    2^SF / (BW in kHz, integer) exceeds 16. This differs from the datasheet's "symbol time
    above 16 ms" exactly where the symbol is 16.384 ms long (SF12 at 250 kHz, SF11 at 125 kHz,
    SF10 at 62.5 kHz, SF9 at 31.25 kHz): the firmware leaves it off there. The explicit
    header carries no flag for it, so a receiver that chose the other way could not decode.
    THIS CODE FOLLOWS THE FIRMWARE (rnc_lora_ldro), and a test pins the four cases.
 7. The bit rate the Reticulum RNode interface uses for announce and path timing is
    SF * (4 / CR) / (2^SF / BW) with BW in kHz; this code gives the same figure (rounded to
    an integer); mcu/tests/mcu_radio_reference.sh compares all 320 settings with the
    unmodified reference RNodeInterface.updateBitrate.
 8. Channel access and airtime in the firmware: a CSMA scheme with a slot of 12 symbols
    clamped to 24..100 ms (6 ms minimum above 30 kbit/s), a DIFS of two slots, a random
    contention window; a long term airtime accounting over one hour with limits that the
    host sets in hundredths of a percent. These numbers are used here for the slot and the
    DIFS; the window growth and the budget mechanism are this project's own design.
 9. Boards: pin numbers, chip variants, TCXO voltage selection and whether DIO2 drives the
    antenna switch, as in the table below.

What this implementation adds (none of it changes what is sent): a pending first half is
kept only if it carries exactly 254 bytes; it expires after 2 s plus half the time on air
of a full frame; a frame identical to the pending first half is a duplicate and ignored;
a completed packet is not delivered twice within 10 s; with the Reticulum MTU of 500 a
full size split frame carrying the pending sequence number starts a new packet instead of
being glued to the pending half (the stock receiver cannot tell the two apart); sequence
numbers are chosen to differ from the previous packet's.

Known difference: for a packet of exactly 508 bytes the RNode firmware also sends a third,
header-only frame. This code sends two frames, and ignores a header-only frame that it
receives. Reticulum never sends more than 500 bytes.

Not established
---------------
 - Whether this firmware and a real RNode actually decode each other. Nothing was run on
   air. The derivation may have missed a setting (for example a register the RNode firmware
   sets that does not appear in what was read, or behaviour of the chip not covered by the
   datasheets).
 - The TCXO voltage of each board beyond what the RNode firmware uses (it is the only
   source); a wrong value shows as an oscillator start error at start-up, which this code
   detects (init fails and the interface retries) but cannot fix.
 - Whether the RNode firmware's treatment of the SX126x PA is the best for each power; the
   firmware always uses the +22 dBm PA setting. This code uses the datasheet's optimal
   settings for four power classes, which changes the efficiency, not the format.
 - The CAD parameters (SetCadParams) are values commonly used for 125 kHz bandwidth, not
   taken from a datasheet table I could check; CAD is implemented and model-tested but the
   interface does not use it (it listens for the preamble and header instead).
 - The behaviour of the real chips at the edges of the datasheet's ranges.
 - AXP2101 power management (T-Beam Supreme): not implemented, so that board is listed but
   not supported.

Driver and HAL design
---------------------
The HAL is a table of five hooks (rnc_radio_hal.h): spi_transfer (one transaction with chip
select asserted around exactly that call), gpio_write, gpio_read, delay_us, now_us. Pins
are named by role (reset, busy, dio, rxen, txen); a pin the board lacks reads as -1.

The drivers implement rnc_modem: init (reset, configure, standby), start_rx, poll_rx,
start_tx, poll_tx, carrier, rssi, start_cad, poll_cad, standby, sleep. After init nothing
blocks: the owner calls rnc_lora_if_step every few milliseconds.

SX126x: reset; wait for BUSY; presence check by the sync word registers; SetStandby;
regulator mode (DC-DC when the board has the inductor); TCXO on DIO3 with a start time;
Calibrate; ClearDeviceErrors; CalibrateImage for the band (only the datasheet's bands:
430-440, 470-510, 779-787, 863-870, 902-928 MHz; the calibration commands need STDBY_RC);
SetPacketType LoRa; STDBY_XOSC and a check that the oscillator started; DIO2 as RF switch;
SetRfFrequency (freq * 2^25 /
32 MHz); SetPaConfig and SetTxParams (SX1262 -9..+22 dBm in four power classes, SX1261
-17..+15 dBm), the over-current register, the TX clamp register of the antenna mismatch
erratum; buffer bases; modulation parameters with the low data rate flag and the 500 kHz
register of the modulation quality erratum; packet parameters (explicit header, CRC on,
standard IQ) followed by the IQ polarity register fix of the erratum (the command resets
bit 2 of 0x0736; a model reproduces the silent receive failure if the fix is missing); sync
word; boosted receiver gain; all interrupts routed to DIO1; fallback mode STDBY_XOSC.
Reception reads GetIrqStatus (only when DIO1 is high, if the line exists), the buffer
status, the buffer, the packet status (RSSI, SNR). The carrier is declared busy from a
preamble detection until header error, CRC error, reception end or the time a frame can last.

SX127x: reset; version check (0x12); sleep then LoRa sleep (the LoRa bit changes only in
sleep); frequency (freq * 2^19 / 32 MHz); FIFO bases; LNA boost; bandwidth/coding
rate/explicit header; spreading factor and CRC; AGC auto plus the low data rate flag;
detection optimise and threshold; preamble register; sync word 0x12; standard IQ
registers; the 500 kHz bandwidth errata registers; PA configuration for PA_BOOST (2..17 dBm,
18..20 with the PA DAC) or RFO (0..14 dBm) and the matching over-current setting. Header
mode can be switched to implicit (needed only for SF6, which the interface does not offer).

Interface adapter (rnc_lora_if): a queue of three packets; each is checked against the
airtime budget (a packet longer than the whole budget is dropped as unsendable), waits for
the channel (DIFS plus a random window, frozen while the channel is busy, growing after
interruptions), is checked against the budget again when the channel is won, books its
airtime, sends its frames back to back, and the radio returns to receive. A queued packet
older than 60 s is dropped. A radio that fails to start or to resume is retried every 10 s
and the application announces when it comes up.

Modes and configuration
-----------------------
lora.mode off      (default) no radio.
lora.mode leaf     LoRa is the node's only interface. It announces on LoRa, answers /echo and
                   /info over LoRa, forwards nothing (no transport). The serial or Wi-Fi
                   interface is not used; the serial port is free for status text.
lora.mode gateway  the serial or Wi-Fi interface (as chosen by "mode") plus LoRa, with
                   Reticulum transport ON: the board forwards between them, so a host node
                   reaches the LoRa network through it. The mcu profile's tables are small
                   (2 interfaces, 12 paths, 8 remembered announces, 4 queued announces,
                   8 link table entries): this is a small gateway, not a repeater for a
                   busy network. Transport is OFF in every other mode.
If leaf is requested but the radio cannot be used (settings incomplete, board not
supported), the board falls back to its serial or Wi-Fi leaf behaviour instead of going
silent.

Keys (same console, tools and storage ideas as the Wi-Fi provisioning, mcu/README.txt):
  lora.mode     off | leaf | gateway
  lora.freq     Hz (868100000) or MHz with a decimal point (868.1); 137 to 1020 MHz
  lora.bw       Hz (125000) or kHz below 1000 (125, 62.5, 7.8); one of 7.8 10.4 15.6 20.8
                31.25 41.7 62.5 125 250 500 kHz
  lora.sf       5..12 (SX127x boards: 7..12)
  lora.cr       5..8, or 4/5 .. 4/8
  lora.txp      -9..22 dBm at the chip output (limited by the chip and the board)
  lora.airtime  percent of every hour, 0.01 to 100 (default 1)
Console: set lora.freq 868.1 ... save, reboot. Without a console: mcu/tools/wifi-config.sh
--lora-mode ... --lora-freq ... (see its header). Storage: ESP-IDF NVS partition "rnccfg",
Arduino ESP32 Preferences "rnc_net", nRF52 the internal file system (/rnc_lora). The
build selects the BOARD (Kconfig choice RETICULUM_MCU_LORA_BOARD in ESP-IDF, the
environment name in PlatformIO), never the frequency or power.

Boards
------
Pin numbers are chip GPIO numbers (nRF52: port * 32 + pin). "Confidence" is how sure I am
that the entry is right; nothing was tested on a board.

 id (PlatformIO env)       chip     SCK MISO MOSI  CS RST BUSY DIO  other                  confidence
 heltec_wifi_lora_32_V3    SX1262     9   11   10   8  12   13  14  TCXO 3.3 V, DIO2 sw.  pins medium-high (RNode
                           ESP32-S3                                                         firmware), TCXO voltage
                                                                                            medium-low
 heltec_wifi_lora_32_V2    SX1276     5   19   27  18  14    -  26  PA_BOOST               pins medium (SPI pins are the
                           ESP32                                                            common ESP32 LoRa wiring)
 ttgo_t_beam (v1.0/v1.1)   SX1276     5   19   27  18  23    -  26  PA_BOOST, AXP192      pins medium; the AXP192 LDO2
                           ESP32                                    LDO2 -> radio, I2C      sequence is from the data
                                                                    SDA 21 SCL 22           sheet, untested; v1.2 (AXP2101)
                                                                                            NOT supported
 lilygo_t_beam_supreme     SX1262    12   13   11  10   5    4   1  AXP2101 needed         pins medium; NOT SUPPORTED
                           ESP32-S3                                                         (no PMU driver)
 lilygo_t3_s3 (SX1262)     SX1262     5    3    6   7   8   34  33  TCXO 1.8 V, DIO2 sw.  medium-high; other T3-S3
                           ESP32-S3                                                         variants (SX1276, SX1280,
                                                                                            LR1121) are not described
 wiscore_rak4631           SX1262    43   45   44  42  38   46  47  RXEN 37 (switch       pins medium-high; TCXO 3.3 V
                           nRF52840                                  supply), DIO2 sw.      medium-low
 heltec_t114               SX1262    19   23   22  24  25   17  20  TCXO 1.8 V, DIO2 sw.  medium
                           nRF52840
 lilygo_t_echo             SX1262    19   23   22  24  25   17  20  TCXO 1.8 V, VEXT P0.12 medium-low: the RNode firmware
                           nRF52840                                  high, DIO2 sw.         does not enable DIO2 here;
                                                                                            this table does

Not offered as an environment: the T-Beam Supreme (no PlatformIO board definition used,
and the PMU is not supported), the T-Deck, boards with SX1280 or LR1121.

Tests (all on the host, label mcu; none of them proves anything about real radios)
----------------------------------------------------------------------------------
 reticulum_mcu_radio            core arithmetic and framing (time on air against widely published
                                 values and an independent implementation of the formula over
                                 the whole grid; the 254/255/256/500/508 boundary; a differential
                                 check against a receiver written from the stock rules; airtime
                                 budget; CSMA; settings), the two drivers against the chip
                                 models (command and register sequences, every bandwidth,
                                 spreading factor, coding rate and power class, frames between
                                 the two families), the interface on a simulated medium (loss,
                                 collision, hidden node, budget over two hours, queue, retry),
                                 the portable application talking Reticulum over simulated LoRa
                                 (announce, path request, links, /echo and /info with packets up
                                 to 483 bytes, a lossy channel, leaf versus gateway), and the
                                 regulatory gate.
 reticulum_mcu_radio_mutations  breaks the header layout, the split reassembly, the sync word,
                                 the airtime limiter and 25 other things (30 mutations in
                                 all) in a scratch copy and requires the tests to fail for each.
 reticulum_mcu_gateway          a default-build reticulum-c-node reaches the /echo and /info of a
                                 simulated board behind a simulated gateway board (the firmware
                                 logic over TCP plus a modelled radio).
 reticulum_mcu_radio_reference  (with the reference oracle) the bit rate of all 320 settings
                                 against the unmodified reference RNodeInterface.
The models (mcu/tests/radio/) are strict about command order, length and state, but they were
written by the author of the drivers.

Limits
------
 - Not run on any hardware. Not exchanged with any RNode.
 - Half duplex, one radio, one channel, one set of modem settings at a time.
 - No frequency hopping, no FSK, no implicit-header traffic, no Bluetooth, no display.
 - No IFAC.
 - Gateway mode shares the 8-slot event queue and 12-path table of the mcu profile.
 - The time on air uses the configured preamble; an SX127x sends 4 symbols fewer than the
   number configured (the register holds the count minus 4), so the budget is slightly high.
