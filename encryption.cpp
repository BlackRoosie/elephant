#include <iostream>
#include "constants.h"

unsigned char rotationLeft3(unsigned char word){
    return (word << 3 | word >> 5);
}

void lfsr_granger(unsigned char* state){

    unsigned char temp = rotationLeft3(state[0]) ^ (state[3] << 7) ^ (state[13] >> 7);
    
    for(int i = 0; i < (NBYTES-1); i++)
        state[i] = state[i+1];
    
    state[NBYTES-1] = temp;
    
}