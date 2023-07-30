#include<iostream>
#include "constants.hpp"
#include "aead.hpp"
#include "api.hpp"

using namespace std;

void encryption(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* plaintext, int ptlen, unsigned char* ciphertext, unsigned char* tag) {

	crypto_aead(key, nonce, ad, adlen, plaintext, ptlen, ciphertext, tag, 1);
}

void decryption(unsigned char* key, unsigned char* nonce, unsigned char* ad, int adlen, unsigned char* ciphertext, int ctlen, unsigned char* plaintextDecrypted, unsigned char* tagEncryption, unsigned char* tagDecryption) {

	crypto_aead(key, nonce, ad, adlen, ciphertext, ctlen, plaintextDecrypted, tagDecryption, 0);

	bool tag_equality = true;
	for (int i = 0; i < 8; i++) {
		if (tagEncryption[i] != tagDecryption[i]) {
			tag_equality = false;
			break;
		}
	}

	if (tag_equality)
		for (int i = 0; i < ctlen; i++)
			cout << plaintextDecrypted[i];
	else
		cout << "Different tags" << endl;
}