#include<iostream>

#include "constants.h"
// #include "spongent.cpp"
#include "encryption.cpp"

#include <bitset>

using namespace std;

void randomBytes(unsigned char* bytes, int n) {

    int temp;
	for (int i = 0; i < n; i++)
	{
		temp = rand();
		bytes[i] = temp & 255;
	}
}

void encrytpion(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag){
    crypto_aead(key, nonce, ad, adlen, plaintext, ptlen, ciphertext, tag);
}

void decryption(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* ciphertext, int ctlen, unsigned char* plaintextDecrypted, unsigned char* tagEncryption, unsigned char* tagDecryption){
    crypto_aead(key, nonce, ad, adlen, ciphertext, ctlen, plaintextDecrypted, tagDecryption);
    bool tag_equality = true;
	for(int i = 0; i < 16; i++){
		if(tagEncryption[i] != tagDecryption[i]){
			tag_equality = false;
			break;
		}
	}

	if(tag_equality)
		for(int i = 0; i < ctlen; i++)
			cout<<plaintextDecrypted[i]<<'\t';
	else
		cout<<"Different tags"<<endl;
}

int main(){

    unsigned char key[KEYBYTES];
    unsigned char nonce[NONCEBYTES];

    randomBytes(key, KEYBYTES);
	randomBytes(nonce, NONCEBYTES);

    unsigned char ad[5] = {'A', 'S', 'C', 'O', 'N'};
    int adlen = sizeof(ad);	
    
    unsigned char plain[5] = {'a', 's', 'c', 'o', 'n'};
    const int msglen = sizeof(plain);	

    unsigned char cipher[msglen];
	unsigned char plaintextDecryted[msglen];
	unsigned char tagEncryption[TAGBYTES];
	unsigned char tagDecryption[TAGBYTES];

    encrytpion(key, nonce, ad, adlen, plain, msglen, cipher, tagEncryption);

    // for(int i = 0; i < msglen; i++)
    //     cout<<bitset<8>(cipher[i])<<endl;

    decryption(key, nonce, ad, adlen, cipher, msglen, plaintextDecryted, tagEncryption, tagDecryption); 

    // cout<<endl;
    // for(int i = 0; i < msglen; i++)
    //     cout<<bitset<8>(plaintextDecryted[i])<<endl;

    // for(int i = 0; i < msglen; i ++)
    //     cout<<plaintextDecryted[i]<<endl;

    // cout<<bitset<8>('e')<<endl;
    // unsigned char trial = reverse('e');
    // cout<<bitset<8>(trial)<<endl;

    // cout<<bitset<8>(lCounter(0x75));
    // cout<<bitset<8>(getBit(0x40, 1))<<endl;

    // unsigned char state[NBYTES] = {0};
    // state[0] = 0xff;
    // pLayer(state);
    // for(int i =0; i < NBYTES; i++)
    //     cout<<"i: "<<bitset<8>(state[i])<<endl;

    // cout<<bitset<8>(rotationLeft3(0x9a));

    // unsigned char state[NBYTES] = {0};
    // state[0] = 0x9a;
    // state[1] = 0x01;
    // state[3] = 0x01;
    // state[13] = 0x80;
    // state[19] = 0x20;

    // lfsr_granger(state);

    // for(int i =0; i < NBYTES; i++)
    //     cout<<i<<" : "<<bitset<8>(state[i])<<endl;


    return 0;
}
