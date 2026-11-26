/* Test double for libloragw: records the configuration and transmissions, and delivers
 * injected received frames. Only the calls rnc_sx1302.c makes. */
#include "loragw_hal.h"
#include <string.h>
#include <stdio.h>
int starts, sends; struct lgw_pkt_tx_s last_tx[4]; struct lgw_conf_rxif_s svc; struct lgw_conf_board_s brd; struct lgw_tx_gain_lut_s lut0;
struct lgw_pkt_rx_s inject[8]; int n_inject;
int lgw_board_setconf(struct lgw_conf_board_s *c){brd=*c;return 0;}
int lgw_rxrf_setconf(uint8_t r, struct lgw_conf_rxrf_s *c){(void)r;(void)c;return 0;}
int lgw_rxif_setconf(uint8_t i, struct lgw_conf_rxif_s *c){if(i==8)svc=*c;return 0;}
int lgw_txgain_setconf(uint8_t r, struct lgw_tx_gain_lut_s *c){(void)r;lut0=*c;return 0;}
int lgw_start(void){starts++;return 0;}
int lgw_stop(void){return 0;}
int lgw_receive(uint8_t max, struct lgw_pkt_rx_s *p){int n=n_inject<max?n_inject:max;memcpy(p,inject,sizeof(*p)*n);n_inject=0;return n;}
int lgw_send(struct lgw_pkt_tx_s *t){if(sends<4)last_tx[sends]=*t;sends++;return 0;}
int lgw_status(uint8_t r,uint8_t s,uint8_t *c){(void)r;(void)s;*c=TX_FREE;return 0;}
int lgw_abort_tx(uint8_t r){(void)r;return 0;}
uint32_t lgw_time_on_air(const struct lgw_pkt_tx_s *t){(void)t;return 5;}
