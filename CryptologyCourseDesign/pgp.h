#pragma once
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/comp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <ctime>

class pgp
{
public:
	static void CreateECKeys(const char* filepath_pub, const char* filepath_pri);
	static void CreateRSAKeys(const char* filepath_pub, const char* filepath_pri);
	static void Signature(const char * filepath_pri, const unsigned char * dig, unsigned int dlen, unsigned char * sig, unsigned int * sig_len);
	static void Digest(const char* msg, int len, unsigned char* dig, unsigned int * dig_len);
	static int Verify(const char* filepath_pub, const unsigned char* dig, unsigned int dlen, unsigned char* sig, unsigned int s);
	static void Encrypt(char* filepath_pub, unsigned char* msg, int msg_len, unsigned char* r, int *r_len);
	static void Decrypt(const char* filepath_pri, unsigned char* msg, int msg_len, unsigned char* r, int *r_len);
};

