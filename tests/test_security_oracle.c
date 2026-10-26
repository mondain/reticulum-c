#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <reticulum_c/rnc_security.h>
#include <reticulum_c/rnc_node.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Optional C driver for the unchanged external RNS implementation. No Python
 * source is authored or executed by this harness. CPython is an oracle-only
 * dependency, never linked into reticulum_c. */
#define CHECK(x) do {if(!(x)){if(PyErr_Occurred())PyErr_Print();fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
static PyObject *must(PyObject *p){CHECK(p);return p;}
static PyObject *bytes(const void *p,size_t n){return must(PyBytes_FromStringAndSize(p,(Py_ssize_t)n));}
static void same(PyObject *o,const void *p,size_t n){CHECK(PyBytes_Check(o)&&PyBytes_Size(o)==(Py_ssize_t)n&&!memcmp(PyBytes_AsString(o),p,n));}
static rnc_result random_bytes(void *context,uint8_t *out,size_t n){uint8_t *v=context;size_t i;for(i=0;i<n;i++)out[i]=(*v)++;return RNC_OK;}
static void path(const char *text){PyObject *value=must(PyUnicode_FromString(text));CHECK(PyList_Insert(PySys_GetObject("path"),0,value)==0);Py_DECREF(value);}
static void ifac_oracle(PyObject *rns) {
    rnc_ifac cfg;rnc_packet packet={0};uint8_t raw[500],wire[564],out[500],origin[64];size_t n,w,k;
    PyObject *types,*nstype,*ns,*idclass,*pyid,*transport,*rawbytes,*encoded,*decoded,*keybytes,*tag,*material,*crypto,*hkdf,*reticulum,*salt,*derived,*one,*two;
    CHECK(rnc_ifac_init(&cfg,"mesh",4,"secret",6,8)==RNC_OK);
    packet.flags=RNC_PLAIN<<2;packet.context=0;packet.data_size=2;memcpy(packet.data,"hi",2);
    CHECK(rnc_plain_destination_hash("test.ifac",packet.destination)==RNC_OK);
    CHECK(rnc_packet_encode(&packet,raw,sizeof(raw),&n)==RNC_OK);
    CHECK(rnc_ifac_apply(&cfg,raw,n,wire,sizeof(wire),&w)==RNC_OK);
    types=must(PyImport_ImportModule("types"));nstype=must(PyObject_GetAttrString(types,"SimpleNamespace"));ns=must(PyObject_CallNoArgs(nstype));
    idclass=must(PyObject_GetAttrString(rns,"Identity"));keybytes=bytes(cfg.key,64);
    pyid=must(PyObject_CallMethod(idclass,"from_bytes","O",keybytes));
    CHECK(PyObject_SetAttrString(ns,"ifac_identity",pyid)==0&&PyObject_SetAttrString(ns,"ifac_key",keybytes)==0);
    tag=must(PyLong_FromLong(8));CHECK(PyObject_SetAttrString(ns,"ifac_size",tag)==0);
    transport=must(PyObject_GetAttrString(rns,"Transport"));rawbytes=bytes(raw,n);
    encoded=must(PyObject_CallMethod(transport,"handle_outgoing_ifac","OO",ns,rawbytes));same(encoded,wire,w);
    CHECK(rnc_ifac_verify(&cfg,(const uint8_t*)PyBytes_AsString(encoded),(size_t)PyBytes_Size(encoded),out,sizeof(out),&k)==RNC_OK&&k==n&&!memcmp(raw,out,n));
    decoded=must(PyObject_CallMethod(transport,"handle_ifac","OO",encoded,ns));CHECK(PyTuple_Check(decoded)&&PyTuple_Size(decoded)==2&&PyObject_IsTrue(PyTuple_GetItem(decoded,0)));same(PyTuple_GetItem(decoded,1),raw,n);
    /* Independently ask the reference for the complete derivation pipeline. */
    one=must(PyObject_CallMethod(idclass,"full_hash","y#","mesh",(Py_ssize_t)4));
    two=must(PyObject_CallMethod(idclass,"full_hash","y#","secret",(Py_ssize_t)6));
    CHECK(PyBytes_Size(one)==32&&PyBytes_Size(two)==32);memcpy(origin,PyBytes_AsString(one),32);memcpy(origin+32,PyBytes_AsString(two),32);Py_DECREF(one);Py_DECREF(two);
    material=must(PyObject_CallMethod(idclass,"full_hash","y#",origin,(Py_ssize_t)64));crypto=must(PyObject_GetAttrString(rns,"Cryptography"));hkdf=must(PyObject_GetAttrString(crypto,"hkdf"));reticulum=must(PyObject_GetAttrString(rns,"Reticulum"));salt=must(PyObject_GetAttrString(reticulum,"IFAC_SALT"));
    one=must(PyLong_FromLong(64));two=must(PyTuple_Pack(3,one,material,salt));derived=must(PyObject_CallObject(hkdf,two));same(derived,cfg.key,64);
    Py_DECREF(two);Py_DECREF(one);Py_DECREF(derived);Py_DECREF(salt);Py_DECREF(reticulum);Py_DECREF(hkdf);Py_DECREF(crypto);Py_DECREF(material);
    Py_DECREF(decoded);Py_DECREF(encoded);Py_DECREF(rawbytes);Py_DECREF(transport);Py_DECREF(tag);Py_DECREF(pyid);Py_DECREF(keybytes);Py_DECREF(idclass);Py_DECREF(ns);Py_DECREF(nstype);Py_DECREF(types);
    rnc_ifac_clear(&cfg);puts("IFAC exact wire and key derivation: C <-> unmodified RNS passed");
}
static void token_oracle(PyObject *rns) {
    rnc_identity owner;rnc_ratchet_key key;rnc_ratchets store;rnc_group_key group;
    uint8_t random=1,identitybytes[64],token[500],plain[500],wire[500];size_t i,n,w;
    PyObject *idclass,*keybytes,*pyid,*ratchets,*privatekey,*publickey,*message,*encrypted,*decrypted,*ctoken,*crypto,*tokenclass,*gkey,*pytoken,*groupencrypted;
    for(i=0;i<64;i++)identitybytes[i]=(uint8_t)i;
    CHECK(rnc_identity_from_private(&owner,identitybytes)==RNC_OK);
    CHECK(rnc_ratchets_init(&store,&owner,&key,1,1800)==RNC_OK&&rnc_ratchets_rotate(&store,100,random_bytes,&random)==RNC_OK);
    idclass=must(PyObject_GetAttrString(rns,"Identity"));keybytes=bytes(identitybytes,64);pyid=must(PyObject_CallMethod(idclass,"from_bytes","O",keybytes));
    privatekey=bytes(key.private_key,32);publickey=bytes(key.public_key,32);ratchets=must(PyList_New(1));Py_INCREF(privatekey);PyList_SET_ITEM(ratchets,0,privatekey);
    message=bytes("C security interoperability",27);
    CHECK(rnc_ratchet_encrypt(&owner,key.public_key,"C security interoperability",27,random_bytes,&random,token,sizeof(token),&n)==RNC_OK);
    ctoken=bytes(token,n);decrypted=must(PyObject_CallMethod(pyid,"decrypt","OOO",ctoken,ratchets,Py_True));same(decrypted,"C security interoperability",27);Py_DECREF(decrypted);
    encrypted=must(PyObject_CallMethod(pyid,"encrypt","OO",message,publickey));
    CHECK(rnc_ratchets_decrypt(&store,&owner,1,(const uint8_t*)PyBytes_AsString(encrypted),(size_t)PyBytes_Size(encrypted),plain,sizeof(plain),&w,NULL)==RNC_OK&&w==27&&!memcmp(plain,"C security interoperability",27));
    CHECK(rnc_group_generate(&group,random_bytes,&random)==RNC_OK);gkey=bytes(group.bytes,64);
    crypto=must(PyObject_GetAttrString(rns,"Cryptography"));tokenclass=must(PyObject_GetAttrString(crypto,"Token"));pytoken=must(PyObject_CallOneArg(tokenclass,gkey));
    CHECK(rnc_group_encrypt(&group,"group data",10,random_bytes,&random,wire,sizeof(wire),&n)==RNC_OK);
    {PyObject *b=bytes(wire,n);decrypted=must(PyObject_CallMethod(pytoken,"decrypt","O",b));same(decrypted,"group data",10);Py_DECREF(decrypted);Py_DECREF(b);}
    {PyObject *b=bytes("group data",10);groupencrypted=must(PyObject_CallMethod(pytoken,"encrypt","O",b));Py_DECREF(b);}
    CHECK(rnc_group_decrypt(&group,(const uint8_t*)PyBytes_AsString(groupencrypted),(size_t)PyBytes_Size(groupencrypted),plain,sizeof(plain),&w)==RNC_OK&&w==10&&!memcmp(plain,"group data",10));
    Py_DECREF(groupencrypted);Py_DECREF(pytoken);Py_DECREF(tokenclass);Py_DECREF(crypto);Py_DECREF(gkey);Py_DECREF(encrypted);Py_DECREF(ctoken);Py_DECREF(message);Py_DECREF(ratchets);Py_DECREF(publickey);Py_DECREF(privatekey);Py_DECREF(pyid);Py_DECREF(keybytes);Py_DECREF(idclass);
    rnc_group_clear(&group);rnc_ratchets_clear(&store);rnc_identity_clear(&owner);
    puts("Ratchet and GROUP encryption/decryption: C <-> unmodified RNS passed");
}
static void announce_oracle(PyObject *rns) {
    rnc_identity owner;rnc_ratchet_key ratchet;rnc_packet packet;uint8_t random=77,key[64],raw[500];size_t i,n;
    PyObject *packetclass,*args,*b,*p,*idclass,*ok,*destclass,*dest;
    for(i=0;i<64;i++)key[i]=(uint8_t)i;
    CHECK(rnc_identity_from_private(&owner,key)==RNC_OK&&rnc_ratchet_generate(&ratchet,100,random_bytes,&random)==RNC_OK);
    CHECK(rnc_announce_create_ratchet(&owner,"test.oracle",ratchet.public_key,"metadata",8,100,random_bytes,&random,&packet)==RNC_OK&&rnc_packet_encode(&packet,raw,sizeof(raw),&n)==RNC_OK);
    packetclass=must(PyObject_GetAttrString(rns,"Packet"));b=bytes(raw,n);args=must(PyTuple_Pack(2,Py_None,b));p=must(PyObject_CallObject(packetclass,args));
    ok=must(PyObject_CallMethod(p,"unpack",NULL));CHECK(PyObject_IsTrue(ok));Py_DECREF(ok);
    idclass=must(PyObject_GetAttrString(rns,"Identity"));ok=must(PyObject_CallMethod(idclass,"validate_announce","OO",p,Py_True));CHECK(PyObject_IsTrue(ok));
    CHECK(rnc_plain_destination_hash("test.plain",raw)==RNC_OK);destclass=must(PyObject_GetAttrString(rns,"Destination"));dest=must(PyObject_CallMethod(destclass,"hash","Oss",Py_None,"test","plain"));same(dest,raw,16);
    Py_DECREF(dest);
    CHECK(rnc_path_request_create(owner.hash,NULL,ratchet.public_key,16,&packet)==RNC_OK);
    dest=must(PyObject_CallMethod(destclass,"hash","Osss",Py_None,"rnstransport","path","request"));same(dest,packet.destination,16);
    Py_DECREF(dest);Py_DECREF(destclass);Py_DECREF(ok);Py_DECREF(idclass);Py_DECREF(p);Py_DECREF(b);Py_DECREF(args);Py_DECREF(packetclass);rnc_ratchet_clear(&ratchet);rnc_identity_clear(&owner);
    puts("Ratcheted announce signature and PLAIN destination: unmodified RNS accepted");
}
int main(int argc,char **argv) {
    PyObject *rns;
    if(argc<2||argc>3){fprintf(stderr,"usage: %s PINNED_RNS_CHECKOUT [ORACLE_DEPENDENCIES]\n",argv[0]);return 2;}
    Py_Initialize();if(argc==3)path(argv[2]);path(argv[1]);rns=must(PyImport_ImportModule("RNS"));
    ifac_oracle(rns);token_oracle(rns);announce_oracle(rns);Py_DECREF(rns);
    CHECK(Py_FinalizeEx()==0);return 0;
}
