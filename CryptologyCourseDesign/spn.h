#pragma once
#include "FormatExchange.h"

using namespace std;



class spn
{
public:
	spn(unsigned char* _key);
	~spn();
	Ciphertext Encrypt(char* str, int len);
	void Encrypt(Plaintext plaintext, Ciphertext &ciphertext);
	void Encrypt(bool* text);
	char* Decrypt(Ciphertext ciphertext);
	void Decrypt(Plaintext &plaintext, Ciphertext ciphertext);
	void Decrypt(bool* text);
	unsigned char* GetKey();
	bool* LinearAttack(bool x[][16], bool y[][16], int num); //21~24 29~32
	int LinearAttack(bool x[][16], bool y[][16], int num, bool* _key);
	bool* ViolateAttack(bool x[][16], bool y[][16], bool key[8], int num);

private:
	bool key[32];
	int sbox[16] = { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 };
	int pbox[16] = { 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16 };
	int sbox_r[16] = { 14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5 };
	int pbox_r[16] = { 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16 };
	bool localKey[5][16];

	bool Xor(bool x, bool y);
	void Xor(bool x[], bool y[], int len); // y = x xor y
	void Xor(bool x[], bool y[], bool z[], int len); // z = x xor y 

	void CreateLocalkey();
	void SReplacement(bool* u);
	void SReplacement_R(bool * u);
	void PReplacement(bool* v);
	void PReplacement_R(bool* v);
	bool IsRightKey(bool x[][16], bool y[][16], int num, bool* key);
};

