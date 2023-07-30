#include <iostream>
#include "constants.hpp"
#include "api.hpp"

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

int main() {

	unsigned char key[KEYBYTES];
	unsigned char nonce[NONCEBYTES];

	randomBytes(key, KEYBYTES);
	randomBytes(nonce, NONCEBYTES);

	unsigned char ad[8] = { 'E', 'L', 'E', 'P', 'H', 'A', 'N', 'T' };
	int adlen = sizeof(ad);

	unsigned char plain[8] = { 'e', 'l', 'e', 'p', 'h', 'a', 'n', 't' };
	const int msglen = sizeof(plain);

	unsigned char cipher[msglen];
	unsigned char plaintextDecryted[msglen];
	unsigned char tagEncryption[TAGBYTES] = { 0 };
	unsigned char tagDecryption[TAGBYTES] = { 0 };

	encryption(key, nonce, ad, adlen, plain, msglen, cipher, tagEncryption);

	decryption(key, nonce, ad, adlen, cipher, msglen, plaintextDecryted, tagEncryption, tagDecryption);


	return 0;
}