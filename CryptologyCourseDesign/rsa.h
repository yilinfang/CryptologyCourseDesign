#pragma once

#include <openssl/bn.h>
#include <ctime>
#include <string.h>

class rsa
{
public:
	rsa();
	~rsa();
	void Generate();
	void GeneratePrime(BIGNUM* &bn, int size);
	bool MillerRabin(BIGNUM* bn, int rounds);
	bool IsPrime(BIGNUM* bn, int size);
	void ExpBySquare(BIGNUM* &r, BIGNUM* a, BIGNUM* e, BIGNUM* m);
	void ChineseReminder(BIGNUM* &r, BIGNUM* p, BIGNUM* q, BIGNUM* a, BIGNUM* e, BIGNUM* m);
	void GetInverse(BIGNUM* &r, BIGNUM* n, BIGNUM* m);
	void Montgomery(BIGNUM* &r,BIGNUM* A, BIGNUM* B);
	void Montgomery(BIGNUM* &r);
	void Montgomery_Inverse(BIGNUM* &r);
	void ExpBySquare_mont(BIGNUM* &r, BIGNUM* a, BIGNUM* e); 
	void Encrypt(unsigned char* input, unsigned char* output, int size);
	char* Encrypt(char* input);
	void Encrypt(unsigned char* input, int len, char* &output);
	void Decrypt(unsigned char* input, unsigned char* output, int size);
	char* Decrypt(char* input);
	char* Decrypt_mont(char* input);
	char* Decrypt_reminder(char* input);
	void Decrypt(char* input, unsigned char* &output, int &len);
private:
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* n;
	BIGNUM* n_eular;
	BIGNUM* n_inv;
	BIGNUM* n_;
	BIGNUM* e;
	BIGNUM* d;
	BIGNUM* R;
	BIGNUM* R_inv;
	BIGNUM* p_;
	BIGNUM* q_;
};

