/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */

// uint8_t x[ 16 ] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
// x=10:000102030405060708090A0B0C0D0E0F

// -----------------------------------------------------------

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

// ----------------------------------------------------------------













uint8_t hexCharToNum(char c){
  return c > '9' ? c - 55 : c - '0';
}

// llallalal
// void numToHex(uint8_t n, char* arr, int startIndex){
//     char hex[4];
//     int i = 0;
//     while(n!=0){
//         int mod  = n % 16;
//         hex[i] = mod < 10 ? mod + '0' : mod + 55;
//         i++;
//         n /= 16;
//     }
//     if(i == 1){
//       hex[1] = '0';
//       i = 2;
//     }
//     for(int j=i-1; j>=0; j--){
//         // arr[startIndex++] = hex[j];
//         scale_uart_wr(SCALE_UART_MODE_BLOCKING, hex[j]);
//     }
// }

int _octetstr_rd( uint8_t* r, int n_r, char* x){
  uint8_t size = hexCharToNum(x[0]) * 16 + hexCharToNum(x[1]);
  for(int currentChar = 0; currentChar < size; currentChar++){
    uint8_t number = hexCharToNum(x[2*currentChar + 3]) * 16 + hexCharToNum(x[2*currentChar+ 4]);
    r[currentChar] = number;
  }

  return size;
}

int  octetstr_rd( uint8_t* r, int n_r          ) {
     char x[ 2 + 1 + 2 * ( n_r ) + 1 ]; // 2-char length, 1-char colon, 2*n_r-char data, 1-char terminator

     for( int i = 0; true; i++ ) {
       x[ i ] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );

       if( x[ i ] == '\x0D' ) {
         x[ i ] = '\x00'; break;
       }
     }

     return _octetstr_rd( r, n_r, x );
}



/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */



// void extra_octetstr_wr( uint8_t* x, int n_r, char* r ){
//   numToHex(n_r, r, 0);
//   r[2] = ':';
//   for(int currentNum = 0; currentNum < n_r; currentNum++){
//     numToHex(x[currentNum], r, currentNum * 2 + 3);
//   }
// }

void numToHexUart(uint8_t n){
    char hex[4];
    int i = 0;
    while(n!=0){
        int mod  = n % 16;
        hex[i] = mod < 10 ? mod + '0' : mod + 55;
        i++;
        n /= 16;
    }
    if(i == 1){
      hex[1] = '0';
      i = 2;
    }
    if(i == 0){
      hex[0] = '0';
      hex[1] = '0';
      i = 2;
    }
    for(int j=i-1; j>=0; j--){
        // arr[startIndex++] = hex[j];
        scale_uart_wr(SCALE_UART_MODE_BLOCKING, hex[j]);
    }
}

void octetstr_wr( const uint8_t* x, int n_x ) {
  numToHexUart(n_x);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, ':');
  for(int i = 0; i < n_x; i++){
    numToHexUart(x[i]);
  }
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, '\x0D');
  return;
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {
  aes_enc( c, m, k );
  return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) {
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'N');
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'O');
    return -1;
  }

  // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'l');
  // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'a');
  // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'l');
  // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'a');
  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48, 0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13 }, r[ SIZEOF_RND ];
  // char x[] = "hello world";
// hCD (16) , 97 (16) , 16 (16) , E9 (16) , 5B (16) , 42 (16) , DD (16) , 48 (16) , 69 (16) , 77 (16) , 2A (16) , 34 (16) , 6A (16) , 7F (16) , 58 (16) , 13 (16) i):
  // uint8_t k[ SIZEOF_KEY ] = { 0xDB, 0xA2, 0xB8, 0xD5, 0x51, 0x52, 0x8D, 0x31, 0xE1, 0xAC, 0xF4, 0x0D, 0x4B, 0x2D, 0x66, 0x7E }


  while( true ) {
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, '1');
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, '2');
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'G');

    int readstuff = octetstr_rd( cmd, 1 );
    if( 1 !=  readstuff) {
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, readstuff + '0');
      break;
    }
    // read  the GPI     pin, and hence switch : t   <- GPI
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'H');
    bool t = scale_gpio_rd( SCALE_GPIO_PIN_GPI        );
    // write the GPO     pin, and hence LED    : GPO <- t
             scale_gpio_wr( SCALE_GPIO_PIN_GPO, t     );

    // write the trigger pin, and hence LED    : TRG <- 1 (positive edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );
    // write the trigger pin, and hence LED    : TRG <- 0 (negative edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'I');

    // int n = strlen( x );

    // write x = "hello world" to the UART
    // for( int i = 0; i < n; i++ ) {
    //   scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
    // }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'A');
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );
        // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'B');
        break;
      }
      case COMMAND_ENCRYPT : {
        // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'C');
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'D');
        break;
      }
    }
    // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'F');
  }
  // scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'E');
  return 0;
}
