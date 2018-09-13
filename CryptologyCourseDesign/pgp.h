#pragma once
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/comp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <ctime>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class pgp
{
public:
	static void CreateECKeys(const char* filepath_pub, const char* filepath_pri);
	static void CreateRSAKeys(const char* filepath_pub, const char* filepath_pri);
	static void Signature(const char * filepath_pri, const unsigned char * dig, unsigned int dlen, unsigned char * sig, unsigned int * sig_len);
	static void Digest(const unsigned char* msg, int len, unsigned char* dig, unsigned int * dig_len);
	static int Verify(const char* filepath_pub, const unsigned char* dig, unsigned int dlen, unsigned char* sig, unsigned int s);
	static void Encrypt(const char* filepath_pub, unsigned char* msg, int msg_len, unsigned char* r, unsigned *r_len);
	static void Encrypt(unsigned char* key, unsigned char* msg, int msg_len, unsigned char* r, int *r_len);
	static void Encrypt(char * password, const char* filepath_pub, const char* filepath_pri, const char* filepath_in, const char* filepath_out);
	static void Decrypt(const char* filepath_pri, unsigned char* msg, int msg_len, unsigned char* r, unsigned *r_len);
	static void Decrypt(unsigned char* key, unsigned char* msg, int msg_len, unsigned char* r, int *r_len);
	static int Decrypt(const char* filepath_pub, const char* filepath_pri, const char* filepath_in, const char* filepath_out);
};

