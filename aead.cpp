#include <iostream>
#include <cstring>
#include "constants.h"
#include "spongent.cpp"

#include <bitset>

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

void crypto_aead(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* message, int msglen, unsigned char* msgCalculated, unsigned char* tag, bool encrypt){
  
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

    //buffers for storing msgCalculated and tag
    unsigned char buffer[NBYTES];
    unsigned char tag_buffer[NBYTES] = {0};

    //data to store number of blocks of message(msg), msgCalculated and associated data
    //iterations is to set number of iterations in for, which will cover all 3 loops in algorithm
    int blocks_msg, iterations;
    int blocks_cipher = msglen / NBYTES + 1;
    int blocks_ad = (NONCEBYTES + adlen) / NBYTES + 1;

    if(msglen % NBYTES == 0)
        blocks_msg = msglen / NBYTES;
    else 
        blocks_msg = msglen / NBYTES + 1;

    if(blocks_cipher >= (blocks_ad-1))
        iterations = blocks_cipher;
    else 
        iterations = (blocks_ad - 1);

    //processing message 
    permutation(padded_key);
    memcpy(current_mask, padded_key, NBYTES);

    int index = 0;

    for(int i = 0; i < iterations; i++){
        lfsr_granger(current_mask, next_mask);

        //calculating msgCalculated
        if(i < blocks_msg){
            memcpy(buffer, padded_nonce, NBYTES);
            xor_blocks(buffer, current_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            permutation(buffer);
            xor_blocks(buffer, current_mask, NBYTES);
            xor_blocks(buffer, previous_mask, NBYTES);
            if(msglen < NBYTES){
                xor_blocks(buffer, message + index, msglen);
                memcpy(msgCalculated + index, buffer, msglen);
            }
            else{
                xor_blocks(buffer, message + index, NBYTES);
                memcpy(msgCalculated + index, buffer, NBYTES);
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

        //calculating tag using msgCalculated (C in algorithm)
        if(i < blocks_cipher){
            //calculating C_i
            if(msglen >= NBYTES){  
                memcpy(buffer, (encrypt ? msgCalculated : message) + index, NBYTES);
            } 
            else {
                memcpy(buffer, (encrypt ? msgCalculated : message) + index, msglen);
                memset(buffer + msglen, 0x00, NBYTES - msglen);
                buffer[msglen] = 0x80;
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
        msglen -= NBYTES;
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
