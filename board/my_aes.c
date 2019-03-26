#include "my_aes.h"

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
