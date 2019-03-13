#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int uint8_t;

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

void extra_octetstr_wr( uint8_t* x, int n_r, char* r ){
  numToHex(n_r, r, 0);
  r[2] = ':';
  for(int currentNum = 0; currentNum < n_r; currentNum++){
    numToHex(x[currentNum], r, currentNum * 2 + 3);
  }
}

int main(){
  char input[] = "10:000102030405060708090A0B0C0D0E0F";
  uint8_t* output = malloc(16 * sizeof(uint8_t));
  extra_octetstr_rd(input, 16, output);
  for(int i = 0; i < 16; i ++){
    printf("%d ", output[i]);
  }
  strcpy(input,"00000000000000000000000000000000000");
  extra_octetstr_wr(output, 16, input);
  printf("\n%s\n", input);

  return 0;
}
