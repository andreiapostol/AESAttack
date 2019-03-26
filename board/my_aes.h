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

aes_gf28_t aes_gf28_add( aes_gf28_t , aes_gf28_t  );
aes_gf28_t aes_gf28_mulx( aes_gf28_t  );
aes_gf28_t aes_gf28_mul( aes_gf28_t , aes_gf28_t  );
aes_gf28_t aes_gf28_inv( aes_gf28_t  );
aes_gf28_t aes_enc_sbox( aes_gf28_t  );
aes_gf28_t aes_dec_sbox( aes_gf28_t  );
void aes_enc_keyexp_step( uint8_t* , const uint8_t* , uint8_t );
void aes_enc_rnd_key( aes_gf28_t* , const aes_gf28_t*  );
void aes_enc_sub_key( aes_gf28_t* , const aes_gf28_t*  );
void aes_enc_rnd_sub(        aes_gf28_t* );
void aes_enc_rnd_row(        aes_gf28_t* );
void aes_enc_rnd_mix(        aes_gf28_t* );
void aes_enc( uint8_t* , const uint8_t* , const uint8_t*  );
