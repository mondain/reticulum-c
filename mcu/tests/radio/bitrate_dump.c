/* Prints the bit rate of the LoRa interface for every spreading factor, bandwidth and coding
 * rate, in the format of mcu/tests/ref_rnode_bitrate.py ("SF BW CR BITRATE"), for comparison
 * with the figures the unmodified reference RNodeInterface computes. */
#include "../../radio/rnc_lora_phy.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  static const uint32_t bws[10] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000};
  unsigned sf, i, cr;
  for (sf = 5; sf <= 12; sf++)
    for (i = 0; i < 10; i++)
      for (cr = 5; cr <= 8; cr++) {
        rnc_lora_params p;
        memset(&p, 0, sizeof(p));
        p.freq_hz = 868100000u;
        p.bw_hz = bws[i];
        p.sf = (uint8_t)sf;
        p.cr = (uint8_t)cr;
        printf("%u %u %u %u\n", sf, (unsigned)bws[i], cr, (unsigned)rnc_lora_bitrate(&p));
      }
  return 0;
}
