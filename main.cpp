#include<iostream>

#include "constants.h"
#include "spongent.cpp"

#include <bitset>

using namespace std;

void encryption(unsigned char* key, unsigned char*  nonce, unsigned char* ad, unsigned char* message){


}


int main(){

    // unsigned char key[KEYBYTES];
    // unsigned char nonce[NONCEBYTES];

    unsigned char ad[5] = {'A', 'S', 'C', 'O', 'N'};
    // unsigned char plain[5] = {'a', 's', 'c', 'o', 'n'};

    // cout<<bitset<8>('e')<<endl;
    unsigned char trial = reverse('e');
    // cout<<bitset<8>(trial)<<endl;

    // cout<<bitset<8>(lCounter(0x75));
    // cout<<bitset<8>(getBit(0x40, 1))<<endl;

    unsigned char state[NBYTES] = {0};
    state[0] = 0xff;
    pLayer(state);
    for(int i =0; i < NBYTES; i++)
        cout<<"i: "<<bitset<8>(state[i])<<endl;




    return 0;
}
