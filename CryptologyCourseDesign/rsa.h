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
private:
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* n;
	BIGNUM* n_eular;
	BIGNUM* e;
	BIGNUM* d;
	bool IsPrime(BIGNUM* bn, int size);
	void ExpBySquare(BIGNUM* &r, BIGNUM* a, BIGNUM* e, BIGNUM* m);
	void ChineseReminder(BIGNUM);
};

