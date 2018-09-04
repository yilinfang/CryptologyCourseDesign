#pragma once

#include "stdafx.h"
#include <stdlib.h>

using namespace std;

typedef struct Plaintext {
	unsigned char* bufa;
	int len_f;
	int len;
}Plaintext;

typedef struct Ciphertext {
	unsigned char* bufa;
	int len_f;
	int len;
}Ciphertext;

Plaintext String2Plaintext(char* s, int len);
char* Plaintext2String(Plaintext text);

bool* UnsignedChar_A2Bool_A(unsigned char x[], int len);
unsigned char* Bool_A2UnsignedChar_A(bool x[], int len);
void InitCiphertext(Plaintext plaintext, Ciphertext &ciphertext);
void InitPlaintext(Plaintext &plaintext, Ciphertext ciphertext);
void DestroyPlaintext(Plaintext &plaintext);
void DestroyCiphertext(Ciphertext &ciphertext);