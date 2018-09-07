#pragma once
#include "FormatExchange.h"
#include <ctime>

class spn_plus
{
public:

	spn_plus(unsigned char* _key);
	~spn_plus();
	Ciphertext Encrypt(char* str, int len);
	void Encrypt(Plaintext plaintext, Ciphertext &ciphertext);
	void Encrypt(bool* text);
	void ResetSbox(int box_num, int box_size);
	void ResetPbox(int box_num, int box_size);
private:
	bool key[128];
	int sbox[9][32];
	int pbox[128];
	bool localKey[10][128];

	bool Xor(bool x, bool y);
	void Xor(bool x[], bool y[], int len); // y = x xor y
	void Xor(bool x[], bool y[], bool z[], int len); // z = x xor y 

	void CreateLocalkey();
	void SReplacement(bool* u, int* s, int s_len);
	void PReplacement(bool* v, int* p, int s_len);
};

