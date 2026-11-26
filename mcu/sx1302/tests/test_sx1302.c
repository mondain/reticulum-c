/* rnc_sx1302 through rnc_lora_if against the libloragw test double: configuration,
 * restart avoidance, split transmission, loopback reassembly, CRC errors, gain table. */
#include "rnc_lora_if.h"
#include "rnc_sx1302.h"
#include "loragw_hal.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
extern int starts,sends,n_inject; extern struct lgw_pkt_tx_s last_tx[4]; extern struct lgw_conf_rxif_s svc; extern struct lgw_conf_board_s brd; extern struct lgw_pkt_rx_s inject[8]; extern struct lgw_tx_gain_lut_s lut0;
static uint64_t now(void*c){(void)c;struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000ull+t.tv_nsec/1000;}
static uint32_t rnd(void*c){(void)c;return 12345;}
#define CHECK(x) do{if(!(x)){printf("FAIL %s:%d %s\n",__FILE__,__LINE__,#x);return 1;}}while(0)
int main(void){
 static rnc_sx1302 d; static rnc_lora_if li; rnc_sx1302_config cfg={0}; cfg.no_reset=1; cfg.rssi_offset=-215.4f;
 rnc_radio_hal hal={0}; hal.now_us=now;
 rnc_sx1302_init(&d,&cfg); rnc_lora_if_init(&li,&d.modem,&hal,rnd,NULL,10000);
 rnc_lora_params p={915000000,125000,8,5,17,0};
 CHECK(rnc_lora_if_start(&li,&p)==0); CHECK(starts==1); CHECK(brd.lorawan_public==0); CHECK(svc.enable&&svc.bandwidth==BW_125KHZ&&svc.datarate==8);
 CHECK(lut0.size==1&&lut0.lut[0].rf_power==17&&lut0.lut[0].pwr_idx==22);
 p.cr=7; CHECK(rnc_lora_if_reconfigure(&li,&p)==0); CHECK(starts==1);
 p.sf=9; CHECK(rnc_lora_if_reconfigure(&li,&p)==0); CHECK(starts==2);
 p.bw_hz=62500; CHECK(d.modem.ops->check(&d.modem,&p)!=0); p.bw_hz=125000;
 uint8_t pkt[300]; for(int i=0;i<300;i++)pkt[i]=(uint8_t)i;
 CHECK(rnc_lora_if_send(&li,pkt,300,now(0))==0);
 for(int i=0;i<2000&&li.stats.tx_packets==0;i++){rnc_lora_if_step(&li,now(0));usleep(1000);}
 CHECK(li.stats.tx_packets==1); CHECK(sends==2); CHECK(last_tx[0].size==255&&last_tx[1].size==47);
 CHECK(last_tx[0].coderate==CR_LORA_4_7&&last_tx[0].datarate==9&&last_tx[0].rf_power==17&&!last_tx[0].no_crc&&!last_tx[0].invert_pol);
 /* loop both frames back as received */
 for(int i=0;i<2;i++){memset(&inject[i],0,sizeof inject[i]);inject[i].modulation=MOD_LORA;inject[i].status=STAT_CRC_OK;inject[i].size=last_tx[i].size;memcpy(inject[i].payload,last_tx[i].payload,last_tx[i].size);inject[i].rssis=-87.6f;inject[i].snr=7.25f;}
 n_inject=2; uint8_t out[600]; size_t got=0;
 for(int i=0;i<100&&!got;i++){rnc_lora_if_step(&li,now(0));got=rnc_lora_if_recv(&li,out,sizeof out);usleep(4000);}
 CHECK(got==300&&memcmp(out,pkt,300)==0); CHECK(li.stats.last_rssi_dbm==-88&&li.stats.last_snr_quarter_db==29);
 /* bad CRC counted */
 memset(&inject[0],0,sizeof inject[0]);inject[0].modulation=MOD_LORA;inject[0].status=STAT_CRC_BAD;inject[0].size=10;n_inject=1;
 for(int i=0;i<5;i++){rnc_lora_if_step(&li,now(0));usleep(4000);} CHECK(li.stats.rx_crc_errors==1);
 /* low power extrapolation */
 p.txp_dbm=10; CHECK(rnc_lora_if_reconfigure(&li,&p)==0); CHECK(lut0.lut[0].pwr_idx==12&&lut0.lut[0].pa_gain==0);
 printf("all ok\n"); return 0;}
