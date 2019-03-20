/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

#define Nb 4
#define Nr 10
#define AES_ENC_RND_KEY_STEP(a,b,c,d) { \
  s[ a ] = s[ a ] ^ rk[ a ]; \
  s[ b ] = s[ b ] ^ rk[ b ]; \
  s[ c ] = s[ c ] ^ rk[ c ]; \
  s[ d ] = s[ d ] ^ rk[ d ]; \
}

#define AES_ENC_RND_ROW_STEP(a,b,c,d,e,f,g,h) { \
  aes_gf28_t __a1 = s[ a ]; \
  aes_gf28_t __b1 = s[ b ]; \
  aes_gf28_t __c1 = s[ c ]; \
  aes_gf28_t __d1 = s[ d ]; \
  s[ e ] = __a1; \
  s[ f ] = __b1; \
  s[ g ] = __c1; \
  s[ h ] = __d1; \
}

#define AES_ENC_RND_MIX_STEP(a,b,c,d) { \
  aes_gf28_t __a1 = s[ a ]; \
  aes_gf28_t __b1 = s[ b ]; \
  aes_gf28_t __c1 = s[ c ]; \
  aes_gf28_t __d1 = s[ d ]; \
  aes_gf28_t __a2 = aes_gf28_mulx( __a1 ); \
  aes_gf28_t __b2 = aes_gf28_mulx( __b1 ); \
  aes_gf28_t __c2 = aes_gf28_mulx( __c1 ); \
  aes_gf28_t __d2 = aes_gf28_mulx( __d1 ); \
  aes_gf28_t __a3 = __a1 ^ __a2; \
  aes_gf28_t __b3 = __b1 ^ __b2; \
  aes_gf28_t __c3 = __c1 ^ __c2; \
  aes_gf28_t __d3 = __d1 ^ __d2; \
  s[ a ] = __a2 ^ __b3 ^ __c1 ^ __d1; \
  s[ b ] = __a1 ^ __b2 ^ __c3 ^ __d1; \
  s[ c ] = __a1 ^ __b1 ^ __c2 ^ __d3; \
  s[ d ] = __a3 ^ __b1 ^ __c1 ^ __d2; \
}

typedef uint8_t aes_gf28_t;
typedef uint32_t aes_gf28_row_t;
typedef uint32_t aes_gf28_col_t;

aes_gf28_t aes_gf28_add( aes_gf28_t a, aes_gf28_t b ) {
  return a ^ b;
}



aes_gf28_t aes_gf28_mulx( aes_gf28_t a ) {
  // multiplying by X
  if ( ( a & 0x80 ) == 0x80 ) {
    // X^8 = X^4 + X^3 + X^1 + 1 = 0x1B
    // 0x1B = 0 0 0 1 1 0 1 1
    return 0x1B ^ ( a << 1 );
  }else{
    return ( a << 1 );
  }
}

aes_gf28_t aes_gf28_mul( aes_gf28_t a, aes_gf28_t b ) {
  aes_gf28_t t = 0;
  for(int i = 7; i >= 0; i-- ) {
    t = aes_gf28_mulx( t );
    if ( ( b >> i ) & 1 ) {
      t ^= a;
    }
  }
  return t;
}

aes_gf28_t aes_gf28_inv( aes_gf28_t a ) {
  // Compute a ^ 254 based on LaGrange
  aes_gf28_t t_0 = aes_gf28_mul( a, a ); // a ^ 2
  aes_gf28_t t_1 = aes_gf28_mul( t_0, a );
  t_0 = aes_gf28_mul( t_0, t_0 );
  t_1 = aes_gf28_mul( t_1, t_0 );
  t_0 = aes_gf28_mul( t_0, t_0 );
  t_0 = aes_gf28_mul( t_1, t_0 );
  t_0 = aes_gf28_mul( t_0, t_0 );
  t_0 = aes_gf28_mul( t_0, t_0 );
  t_1 = aes_gf28_mul( t_1, t_0 );
  t_0 = aes_gf28_mul( t_0, t_1 );
  t_0 = aes_gf28_mul( t_0, t_0 );
  return t_0;
}

aes_gf28_t aes_enc_sbox( aes_gf28_t a ) {
  a = aes_gf28_inv( a );
  a = ( 0x63    ) ^
      ( a       ) ^
      ( a << 1 ) ^
      ( a << 2 ) ^
      ( a << 3 ) ^
      ( a << 4 ) ^
      ( a >> 7 ) ^
      ( a >> 6 ) ^
      ( a >> 5 ) ^
      ( a >> 4 ) ;
  return a;
}

aes_gf28_t aes_dec_sbox( aes_gf28_t a ) {
  a = ( 0x05    ) ^
  ( a << 1 ) ^
  ( a << 3 ) ^
  ( a << 6 ) ^
  ( a >> 7 ) ^
  ( a >> 5 ) ^
  ( a >> 2 ) ;
  a = aes_gf28_inv( a );
  return a;
}

void aes_enc_keyexp_step( uint8_t* r, const uint8_t* rk, uint8_t rc ) {
r[  0 ] = rc ^ aes_enc_sbox( rk[ 13 ] ) ^ rk[  0 ];
r[  1 ] =       aes_enc_sbox( rk[ 14 ] ) ^ rk[  1 ];
r[  2 ] =       aes_enc_sbox( rk[ 15 ] ) ^ rk[  2 ];
r[  3 ] =       aes_enc_sbox( rk[ 12 ] ) ^ rk[  3 ];
r[  4 ] =                        r[  0 ]    ^ rk[  4 ];
r[  5 ] =                        r[  1 ]    ^ rk[  5 ];
r[  6 ] =                        r[  2 ]    ^ rk[  6 ];
r[  7 ] =                        r[  3 ]    ^ rk[  7 ];
r[  8 ] =                        r[  4 ]    ^ rk[  8 ];
r[  9 ] =                        r[  5 ]    ^ rk[  9 ];
r[ 10 ] =                        r[  6 ]    ^ rk[ 10 ];
r[ 11 ] =                        r[  7 ]    ^ rk[ 11 ];
r[ 12 ] =                        r[  8 ]    ^ rk[ 12 ];
r[ 13 ] =                        r[  9 ]    ^ rk[ 13 ];
r[ 14 ] =                        r[ 10 ]    ^ rk[ 14 ];
r[ 15 ] =                        r[ 11 ]    ^ rk[ 15 ];
}

void aes_enc_rnd_key( aes_gf28_t* s, const aes_gf28_t* rk ) {
  // AES_ENC_RND_KEY_STEP(  0,  1,  2,  3 );
  // AES_ENC_RND_KEY_STEP(  4,  5,  6,  7 );
  // AES_ENC_RND_KEY_STEP(  8,  9, 10, 11 );
  // AES_ENC_RND_KEY_STEP( 12, 13, 14, 15 );
  for(int i = 0; i < 16; i++){
    s[i] = s[i] ^ rk[i];
  }
}

void aes_enc_sub_key( aes_gf28_t* s, const aes_gf28_t* rk ){
  for(int i = 0; i < 16; i++){
    s[i] = aes_enc_sbox(s[i]);
  }
}

void aes_enc_rnd_sub(        aes_gf28_t* s ) {
  for(int i = 0; i < 16; i++ ) {
    s[ i ] = aes_enc_sbox( s[ i ] );
  }
}

void aes_enc_rnd_row(        aes_gf28_t* s ) {
  AES_ENC_RND_ROW_STEP(  1,  5,  9, 13, 13,  1,  5,  9 );
  AES_ENC_RND_ROW_STEP(  2,  6, 10, 14, 10, 14,  2,  6 );
  AES_ENC_RND_ROW_STEP(  3,  7, 11, 15, 7, 11, 15,  3 );
}

void aes_enc_rnd_mix(        aes_gf28_t* s ) {
  AES_ENC_RND_MIX_STEP(  0,  1,  2,  3 );
  AES_ENC_RND_MIX_STEP(  4,  5,  6,  7 );
  AES_ENC_RND_MIX_STEP(  8,  9, 10, 11 );
  AES_ENC_RND_MIX_STEP( 12, 13, 14, 15 );
}

void aes_enc( uint8_t* r, const uint8_t* m, const uint8_t* k ) {
  aes_gf28_t rk[ 4 * Nb ], s[ 4 * Nb ];
  aes_gf28_t rcp[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  // aes_gf28_t *rcp = rcp2;
  aes_gf28_t* rkp = rk;
  // U8_TO_U8_N(    s, m );
  memcpy(s, m, 16 * sizeof(uint8_t));
  // U8_TO_U8_N( rkp, k );
  memcpy(rkp, k, 16 * sizeof(uint8_t));
  aes_enc_rnd_key( s, rkp );
  for(int i = 1; i < Nr; i++ ) {
    aes_enc_rnd_sub( s       );
    aes_enc_rnd_row( s       );
    aes_enc_rnd_mix( s       );
    aes_enc_keyexp_step( rkp, rkp, rcp[i-1] );
    aes_enc_rnd_key( s, rkp );
  }
  aes_enc_rnd_sub( s       );
  aes_enc_rnd_row( s       );
  aes_enc_keyexp_step( rkp, rkp, rcp[Nr - 1] );
  aes_enc_rnd_key( s, rkp );
  // U8_TO_U8_N(    r, s );
  memcpy(r, s, 16 * sizeof(uint8_t));
}


void print_matrix( uint8_t* matrix ){
  for(int i = 0; i < 4; i++){
    printf("\n");
    for(int j = 0; j < 4; j++){
      printf("%2x ", matrix[i + 4 * j]);
    }
  }
  printf("\n");
}

int main( int argc, char* argv[] ) {
  uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
  uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                      0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
  uint8_t t[ 16 ];

  uint8_t u[ 16 ];

  print_matrix(k);
  AES_KEY rk;

  AES_set_encrypt_key( k, 128, &rk );
  AES_encrypt( m, u, &rk );

  print_matrix(m);
  aes_enc(t, m, k);
  print_matrix(t);
  print_matrix(u);
  print_matrix(c);


  if( !memcmp( t, u, 16 * sizeof( uint8_t ) ) ) {
    printf( "AES.Enc( k, m ) == c\n" );
  }
  else {
    printf( "AES.Enc( k, m ) != c\n" );
  }
}
