#include <iostream>
#include "constants.h"
#include "spongent.cpp"

unsigned char rotationLeft3(unsigned char word){
    return (word << 3 | word >> 5);
}

void lfsr_granger(unsigned char* input, unsigned char* output){

    unsigned char temp = rotationLeft3(input[0]) ^ (input[3] << 7) ^ (input[13] >> 7);
    
    for(int i = 0; i < (NBYTES-1); i++)
        output[i] = input[i+1];
    
    output[NBYTES-1] = temp;
    
}

//int size = block size in bytes
void xor_blocks(unsigned char* state, unsigned char* block, int size){
    for(int i = 0; i < size; i++){
        state[i] ^= block[i];
    }
}

void encrypt(unsigned char* key, unsigned char* nonce, int noncelen, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag){
  
    unsigned char padded_key[NBYTES] = {0};   //to store padded key
    unsigned char padded_nonce[NONCEBYTES] = {0}; //to store padded nonce
    memcpy(padded_key, key, KEYBYTES);
    memcpy(padded_nonce, nonce, NONCEBYTES);
    
    unsigned char previous_mask[NBYTES] = {0};
    unsigned char current_mask[NBYTES] = {0};
    unsigned char next_mask[NBYTES] = {0};

    unsigned char buffer[NBYTES];
    unsigned char tag_buffer[NBYTES] = {0};

    //data to store number of blocks of plaintext(msg), ciphertext and associated data
    //iterations is to set number of iterations in for, which will cover all 3 loops in algorithm
    int blocks_msg, iterations;
    int blocks_cipher = ptlen / NBYTES + 1;
    int blocks_ad = (noncelen + adlen) / NBYTES + 1;

    if(ptlen % NBYTES == 0)
        blocks_msg = ptlen / NBYTES;
    else 
        blocks_msg = ptlen / NBYTES + 1;

    if(blocks_cipher >= (blocks_ad-1))
        iterations = blocks_cipher;
    else 
        iterations = (blocks_ad - 1);

    //processing plaintext 
    permutation(padded_key);
    lfsr_granger(padded_key, current_mask);

    int index = 0;
    // int block_size;

    for(int i = 0; i < iterations; i++){
        lfsr_granger(current_mask, next_mask);

        //calculating ciphertext
        if(i < blocks_msg){
            memcpy(buffer, padded_nonce, NBYTES);
            xor_blocks(buffer, current_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            permutation(buffer);
            xor_blocks(buffer, current_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            ptlen -= NBYTES;
            if(ptlen < NBYTES){
                xor_blocks(buffer, plaintext + index, ptlen);
                memcpy(ciphertext + index, buffer, ptlen);
            }
            else{
                xor_blocks(buffer, plaintext + index, NBYTES);
                memcpy(ciphertext + index, buffer, NBYTES);
            }
        }

        //calculating tag using associated data
        if(i > 0 && i < blocks_ad){

        }

        //calculating tag using ciphertext
        if(i < blocks_cipher){

        }
        


    }   




}