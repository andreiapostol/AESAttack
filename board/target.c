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

uint8_t hexCharToNum(char c){
  return c > '9' ? c - 55 : c - '0';
}

void numToHex(uint8_t n, char* arr, int startIndex){
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
    for(int j=i-1; j>=0; j--)
        arr[startIndex++] = hex[j];
}

void extra_octetstr_rd( char* r, int n_r, uint8_t* x){
  uint8_t size = hexCharToNum(r[0]) * 16 + hexCharToNum(r[1]);
  for(int currentChar = 0; currentChar < size; currentChar++){
    uint8_t number = hexCharToNum(r[2*currentChar + 3]) * 16 + hexCharToNum(r[2*currentChar+ 4]);
    x[currentChar] = number;
  }
}

int  octetstr_rd(       uint8_t* r, int n_r ) {
  return 0;
}



/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */



void extra_octetstr_wr( uint8_t* x, int n_r, char* r ){
  numToHex(n_r, r, 0);
  r[2] = ':';
  for(int currentNum = 0; currentNum < n_r; currentNum++){
    numToHex(x[currentNum], r, currentNum * 2 + 3);
  }
}

void octetstr_wr( const uint8_t* x, int n_x ) {
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
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'N');
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'O');
    return -1;
  }

  scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'l');
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'a');
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'l');
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, 'a');
  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0xDB, 0xA2, 0xB8, 0xD5, 0x51, 0x52, 0x8D, 0x31, 0xE1, 0xAC, 0xF4, 0x0D, 0x4B, 0x2D, 0x66, 0x7E }, r[ SIZEOF_RND ];
  char x[] = "hello world";
  while( true ) {

    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }
    // read  the GPI     pin, and hence switch : t   <- GPI
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

    int n = strlen( x );

    // write x = "hello world" to the UART
    for( int i = 0; i < n; i++ ) {
      scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
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
        break;
      }
    }
  }

  return 0;
}
