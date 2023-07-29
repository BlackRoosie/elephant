#include<iostream>

#include "constants.h"
#include "aead.cpp"

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

void encryption(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag){

    crypto_aead(key, nonce, ad, adlen, plaintext, ptlen, ciphertext, tag, 1);
}

void decryption(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* ciphertext, int ctlen, unsigned char* plaintextDecrypted, unsigned char* tagEncryption, unsigned char* tagDecryption){
    
    crypto_aead(key, nonce, ad, adlen, ciphertext, ctlen, plaintextDecrypted, tagDecryption, 0);

    bool tag_equality = true;
	for(int i = 0; i < 8; i++){
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
	unsigned char tagEncryption[TAGBYTES] = {0};
	unsigned char tagDecryption[TAGBYTES] = {0};

    encryption(key, nonce, ad, adlen, plain, msglen, cipher, tagEncryption);

    decryption(key, nonce, ad, adlen, cipher, msglen, plaintextDecryted, tagEncryption, tagDecryption); 

    return 0;
}
