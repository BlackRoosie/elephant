#include <iostream>
#include <cstring>
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

void crypto_aead(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag){
  
    unsigned char padded_key[NBYTES] = {0};   //to store padded key
    unsigned char padded_nonce[NONCEBYTES] = {0}; //to store padded nonce
    memcpy(padded_key, key, KEYBYTES);
    memcpy(padded_nonce, nonce, NONCEBYTES);
    
    //buffers for storing masks
    unsigned char mask_buffer_1[NBYTES] = {0};
    unsigned char mask_buffer_2[NBYTES] = {0};
    unsigned char mask_buffer_3[NBYTES] = {0};

    unsigned char* previous_mask = mask_buffer_1;
    unsigned char* current_mask = mask_buffer_2;
    unsigned char* next_mask = mask_buffer_3;
    unsigned char* temp;

    //buffers for storing ciphertext and tag
    unsigned char buffer[NBYTES];
    unsigned char tag_buffer[NBYTES] = {0};
    if(adlen < NBYTES)
        memcpy(tag_buffer, ad, adlen);
    else 
        memcpy(tag_buffer, ad, NBYTES);

    //data to store number of blocks of plaintext(msg), ciphertext and associated data
    //iterations is to set number of iterations in for, which will cover all 3 loops in algorithm
    int blocks_msg, iterations;
    int blocks_cipher = ptlen / NBYTES + 1;
    int blocks_ad = (NONCEBYTES + adlen) / NBYTES + 1;

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
    memcpy(current_mask, padded_key, NBYTES);

    int index = 0;

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
        if(i < blocks_ad){
            //creating A_i
            if(i == 0){
                memcpy(buffer, nonce, NONCEBYTES);
                if(adlen >= (NBYTES - NONCEBYTES))
                    memcpy(buffer + NONCEBYTES, ad, NBYTES - NONCEBYTES);
                else{
                    memcpy(buffer + NONCEBYTES, ad, adlen);
                    memset(buffer + NONCEBYTES + adlen, 0x00, NBYTES - NONCEBYTES - adlen);
                }

            }
            else{
                if(adlen >= NBYTES){
                    memcpy(buffer, ad + index - NONCEBYTES, NBYTES);
                } 
                else {
                    memcpy(buffer, ad + index - NONCEBYTES, adlen);
                    memset(buffer + adlen, 0x00, NBYTES - adlen);
                    buffer[adlen] = 0x10;
                }
            }

            //calculating tag
            if(i == 0)      //T <- A_1
                memcpy(tag_buffer, buffer, NBYTES);
            else{
                xor_blocks(buffer, previous_mask, NBYTES);
                permutation(buffer);
                xor_blocks(buffer, previous_mask, NBYTES);
                xor_blocks(tag_buffer, buffer, NBYTES);
            }

        }

        //calculating tag using ciphertext
        if(i < blocks_cipher){
            //calculating C_i
            if(ptlen >= NBYTES){    //ptlen = length of plaintext = length of ciphertext
                memcpy(buffer, ciphertext + index, NBYTES);
            } 
            else {
                memcpy(buffer, ciphertext + index, ptlen);
                memset(buffer + ptlen, 0x00, NBYTES - ptlen);
                buffer[ptlen] = 0x10;
            }

            //calculating tag
            xor_blocks(buffer, next_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            permutation(buffer);
            xor_blocks(buffer, next_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            xor_blocks(tag_buffer, buffer, NBYTES);
        }
        
        index += NBYTES;
        ptlen -= NBYTES;
        adlen -= NBYTES;

        temp = previous_mask;
        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = temp;
    }   

    xor_blocks(tag_buffer, padded_key, NBYTES);
    permutation(tag_buffer);
    xor_blocks(tag_buffer, padded_key, NBYTES);
    memcpy(tag, tag_buffer, TAGBYTES);
}
