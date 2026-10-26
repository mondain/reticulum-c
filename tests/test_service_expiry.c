#define main resource_fixture_main
#include "test_resource.c"
#undef main
#include <reticulum_c/rnc_service.h>
/* A response Resource is admitted before its request expires, then finishes
 * after timeout. Its stale completion must release the RX slot so a second
 * valid request/response Resource can complete on the same service. */
typedef struct expiry_case {
    pair links;
    rnc_service *client, *server;
    unsigned admitted, requests, responses, timeouts, first_proof;
    uint8_t id[16], value[10003];
    int expired, second;
} expiry_case;
static void wire(expiry_case *x,rnc_link *from,rnc_link *to,rnc_service *service,int client) {
    rnc_link_event e;
    while(rnc_link_poll(from,&e)==RNC_OK) {
        if(e.type==RNC_LINK_SEND) {
            if(client&&e.packet.context==5)x->first_proof=1;
            CHECK(rnc_link_input(to,&e.packet,x->links.now)==RNC_OK);
        } else if(e.type==RNC_LINK_PACKET||e.type==RNC_LINK_RESOURCE_PACKET) {
            rnc_result r=rnc_service_input(service,&e,x->links.now);
            CHECK(r==RNC_OK||r==RNC_AGAIN);
            if(client&&e.type==RNC_LINK_PACKET&&e.context==2&&r==RNC_OK)x->admitted++;
        }
    }
}
static void app(expiry_case *x,rnc_service *s,int server) {
    rnc_service_event e;uint8_t out[10003];size_t n;
    while(rnc_service_poll(s,&e,out,sizeof(out),&n)==RNC_OK) {
        if(e.type==RNC_SERVICE_REQUEST) {
            CHECK(server&&n==1&&out[0]==0xc0);x->requests++;
            CHECK(rnc_service_respond(s,e.request_id,x->value,sizeof(x->value),x->links.now)==RNC_OK);
        } else if(e.type==RNC_SERVICE_RESPONSE) {
            CHECK(!server&&x->second&&n==sizeof(x->value)&&!memcmp(out,x->value,n));x->responses++;
        } else if(e.type==RNC_SERVICE_TIMEOUT) {
            CHECK(!server);x->timeouts++;
        } else CHECK(0);
    }
}
int main(void) {
    expiry_case x={0};uint8_t nil=0xc0;unsigned i;
    init(&x.links,20000);x.client=rnc_service_new(x.links.a,20000,random_bytes,&x.links.ar);x.server=rnc_service_new(x.links.b,20000,random_bytes,&x.links.br);
    CHECK(x.client&&x.server&&rnc_service_register(x.server,"/echo",RNC_SERVICE_ALLOW_ALL,NULL,0)==RNC_OK);
    x.value[0]=0xc5;x.value[1]=(uint8_t)(10000>>8);x.value[2]=(uint8_t)10000;
    for(i=3;i<sizeof(x.value);i++)x.value[i]=(uint8_t)(i*73u);
    CHECK(rnc_service_request(x.client,"/echo",&nil,1,1000,x.links.now,100,x.id)==RNC_OK);
    for(i=0;i<2000&&!x.responses;i++) {
        CHECK(rnc_service_pump(x.client,x.links.now)==RNC_OK&&rnc_service_pump(x.server,x.links.now)==RNC_OK);
        wire(&x,x.links.a,x.links.b,x.client,1);wire(&x,x.links.b,x.links.a,x.server,0);
        app(&x,x.server,1);app(&x,x.client,0);
        if(x.admitted&&!x.expired) {x.links.now+=200;x.expired=1;}
        if(x.first_proof&&x.expired&&!x.second) {
            x.second=1;CHECK(rnc_service_request(x.client,"/echo",&nil,1,1001,x.links.now,30000,x.id)==RNC_OK);
        }
        x.links.now++;
        CHECK(rnc_service_tick(x.client,x.links.now)==RNC_OK&&rnc_service_tick(x.server,x.links.now)==RNC_OK);
    }
    CHECK(x.expired&&x.second&&x.admitted==2&&x.requests==2&&x.timeouts==1&&x.responses==1);
    rnc_service_free(x.client);rnc_service_free(x.server);finish(&x.links);return 0;
}
