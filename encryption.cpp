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

void encrypt(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag){
  
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
        if(i > 0 && i < blocks_ad){

        }

        //calculating tag using ciphertext
        if(i < blocks_cipher){

        }
        
        index += NBYTES;
        ptlen -= NBYTES;

        temp = previous_mask;
        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = temp;
    }   

}

void decrypt(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* ciphertext, int ctlen, unsigned char* plaintextDecrypted, unsigned char* tagEncryption, unsigned char* tagDecryption){
    
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
    int blocks_cipher = ctlen / NBYTES + 1;
    int blocks_ad = (NONCEBYTES + adlen) / NBYTES + 1;

    if(ctlen % NBYTES == 0)
        blocks_msg = ctlen / NBYTES;
    else 
        blocks_msg = ctlen / NBYTES + 1;

    if(blocks_cipher >= (blocks_ad-1))
        iterations = blocks_cipher;
    else 
        iterations = (blocks_ad - 1);

    //processing ciphertext 
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
            if(ctlen < NBYTES){
                xor_blocks(buffer, ciphertext + index, ctlen);
                memcpy(plaintextDecrypted + index, buffer, ctlen);
            }
            else{
                xor_blocks(buffer, ciphertext + index, NBYTES);
                memcpy(plaintextDecrypted + index, buffer, NBYTES);
            }
        }

        //calculating tag using associated data
        if(i > 0 && i < blocks_ad){

        }

        //calculating tag using ciphertext
        if(i < blocks_cipher){

        }
        
        index += NBYTES;
        ctlen -= NBYTES;

        temp = previous_mask;
        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = temp;
    }   
}