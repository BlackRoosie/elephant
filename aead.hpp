#ifndef AEAD_HPP
#define AEAD_HPP

unsigned char rotationLeft3(unsigned char word);

void lfsr_granger(unsigned char* input, unsigned char* output);

void xor_blocks(unsigned char* state, unsigned char* block, int size);

void crypto_aead(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* message, int msglen, unsigned char* msgCalculated, unsigned char* tag, bool encrypt);
#endif