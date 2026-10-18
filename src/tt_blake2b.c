/*
 * Time-Travel is a real-time file versioning daemon that watches a directory
 * tree via inotify and records every change as compact xdelta3 deltas.
 * Copyright (C) 2026  John (johna124)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Source, issues, contact: https://github.com/johna124
 */
/* tt_blake2b.c — BLAKE2b (RFC 7693), C11 puro, sin SIMD. */
#include "tt_blake2b.h"
#include <string.h>

typedef struct {
    uint64_t h[8], t[2], f[2];
    uint8_t  buf[128];
    size_t   buflen, outlen;
} blake2b_state;

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL };

static const uint8_t blake2b_sigma[12][16] = {
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
 {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
 {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
 {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
 {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
 {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3} };

static uint64_t load64(const void *s){const uint8_t*p=s;
 return ((uint64_t)p[0])|((uint64_t)p[1]<<8)|((uint64_t)p[2]<<16)|((uint64_t)p[3]<<24)|
        ((uint64_t)p[4]<<32)|((uint64_t)p[5]<<40)|((uint64_t)p[6]<<48)|((uint64_t)p[7]<<56);}
static void store64(void *d,uint64_t v){uint8_t*p=d;
 p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);
 p[4]=(uint8_t)(v>>32);p[5]=(uint8_t)(v>>40);p[6]=(uint8_t)(v>>48);p[7]=(uint8_t)(v>>56);}
static uint64_t rotr64(uint64_t x,int n){return (x>>n)|(x<<(64-n));}

#define G(r,i,a,b,c,d) do{ a+=b+m[blake2b_sigma[r][2*(i)]]; d=rotr64(d^a,32); \
 c+=d; b=rotr64(b^c,24); a+=b+m[blake2b_sigma[r][2*(i)+1]]; d=rotr64(d^a,16); \
 c+=d; b=rotr64(b^c,63);}while(0)

static void compress(blake2b_state *S,const uint8_t block[128]){
 uint64_t m[16],v[16];
 for(int i=0;i<16;++i)m[i]=load64(block+i*8);
 for(int i=0;i<8;++i)v[i]=S->h[i];
 v[8]=blake2b_IV[0];v[9]=blake2b_IV[1];v[10]=blake2b_IV[2];v[11]=blake2b_IV[3];
 v[12]=blake2b_IV[4]^S->t[0];v[13]=blake2b_IV[5]^S->t[1];
 v[14]=blake2b_IV[6]^S->f[0];v[15]=blake2b_IV[7]^S->f[1];
 for(int r=0;r<12;++r){
  G(r,0,v[0],v[4],v[8],v[12]);G(r,1,v[1],v[5],v[9],v[13]);
  G(r,2,v[2],v[6],v[10],v[14]);G(r,3,v[3],v[7],v[11],v[15]);
  G(r,4,v[0],v[5],v[10],v[15]);G(r,5,v[1],v[6],v[11],v[12]);
  G(r,6,v[2],v[7],v[8],v[13]);G(r,7,v[3],v[4],v[9],v[14]);}
 for(int i=0;i<8;++i)S->h[i]^=v[i]^v[i+8];
}
static void b2_init(blake2b_state *S,size_t outlen){
 memset(S,0,sizeof*S);
 for(int i=0;i<8;++i)S->h[i]=blake2b_IV[i];
 S->h[0]^=(uint64_t)outlen|(0ULL<<8)|(1ULL<<16)|(1ULL<<24);
 S->outlen=outlen;
}
static void b2_update(blake2b_state *S,const uint8_t *in,size_t inlen){
 while(inlen>0){
  size_t left=S->buflen,fill=128-left;
  if(inlen>fill){S->buflen=128;memcpy(S->buf+left,in,fill);
   S->t[0]+=128;if(S->t[0]<128)S->t[1]++;compress(S,S->buf);
   S->buflen=0;in+=fill;inlen-=fill;}
  else{memcpy(S->buf+left,in,inlen);S->buflen+=inlen;break;}
 }
}
static void b2_final(blake2b_state *S,uint8_t *out){
 S->t[0]+=S->buflen;if(S->t[0]<S->buflen)S->t[1]++;
 S->f[0]=~(uint64_t)0;
 memset(S->buf+S->buflen,0,128-S->buflen);
 compress(S,S->buf);
 uint8_t b[64];for(int i=0;i<8;++i)store64(b+i*8,S->h[i]);
 memcpy(out,b,S->outlen);
}
int tt_blake2b(const void *in,size_t inlen,void *out,size_t outlen){
 if(!out||outlen==0||outlen>TT_BLAKE2B_MAX_LEN)return -1;
 if(!in&&inlen>0)return -1;
 blake2b_state S;b2_init(&S,outlen);
 if(inlen>0)b2_update(&S,in,inlen);
 b2_final(&S,out);return 0;
}
int tt_blake2b_selftest(void){
 static const uint8_t expect[64]={
 0x78,0x6a,0x02,0xf7,0x42,0x01,0x59,0x03,0xc6,0xc6,0xfd,0x85,0x25,0x52,0xd2,0x72,
 0x91,0x2f,0x47,0x40,0xe1,0x58,0x47,0x61,0x8a,0x86,0xe2,0x17,0xf7,0x1f,0x54,0x19,
 0xd2,0x5e,0x10,0x31,0xaf,0xee,0x58,0x53,0x13,0x89,0x64,0x44,0x93,0x4e,0xb0,0x4b,
 0x90,0x3a,0x68,0x5b,0x14,0x48,0xb7,0x55,0xd5,0x6f,0x70,0x1a,0xfe,0x9b,0xe2,0xce};
 uint8_t out[64];
 if(tt_blake2b("",0,out,64)!=0)return -1;
 return memcmp(out,expect,64)==0?0:-1;
}
