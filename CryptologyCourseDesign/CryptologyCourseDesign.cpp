// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "spn_plus.h"
#include "rsa.h"
#include "pgp.h"


using namespace std;


int main()
{
	//rsa Rsa;
	//Rsa.Generate();
	//char s[] = "123abc";
	//char *bufa1, *bufa2;
	//bufa1 = Rsa.Encrypt(s);
	//printf("%s\n", bufa1);
	//bufa2 = Rsa.Decrypt(bufa1);
	//printf("%s\n", bufa2);
	//pgp Pgp;
	//char s[] = "ABC123";
	//unsigned char password[10] = { 1,2,3,4,5,6,7,8,9,0 };
	//unsigned char key[EVP_MAX_KEY_LENGTH];
	//unsigned char iv[EVP_MAX_IV_LENGTH];
	//unsigned char msg[10] = { 0,1,2,3,4,5,6,7,8,9 };
	//EVP_BytesToKey(EVP_aes_256_cfb(), EVP_md5(), NULL, password, 10, 10, key, iv);
	//OpenSSL_add_all_ciphers();
	//EVP_CIPHER_CTX* ctx;
	//ctx = EVP_CIPHER_CTX_new();
	//EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv);
	//int len, _len;
	//len = 0;
	//unsigned char bufa[1000];
	//unsigned char bufa1[1000];
	//unsigned char* p = bufa;
	//EVP_EncryptUpdate(ctx, bufa, &_len, msg, 10);
	//len += _len;
	//EVP_EncryptFinal_ex(ctx, bufa, &_len);
	//len += _len;
	//EVP_CIPHER_CTX_free(ctx);

	//ctx = EVP_CIPHER_CTX_new();
	//EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv);
	//int len1 = 0;
	//EVP_DecryptUpdate(ctx, bufa1, &_len, bufa, len);
	//len1 += _len;
	//EVP_DecryptFinal_ex(ctx, bufa1, &_len);
	//len1 += _len;
	//for (int i = 0; i < len1; i++)
	//{
	//	printf("%d ", bufa1[i]);
	//}
	//pgp.encrypt(s, "d:\\pub_rsa.pem", "d:\\pri_ec.pem", "d:\\input.txt", "d:\\output.txt");
	char s[] = "123abcd";
	pgp::Encrypt(s, "d:\\pub_rsa.pem", "d:\\pri_ec.pem", "d:\\input.txt", "d:\\output1.txt");
	int i = pgp::Decrypt("d:\\pub_ec.pem", "d:\\pri_rsa.pem", "d:\\output1.txt", "d:\\output2.txt");
	printf("%d\n", i);
	//unsigned char msg[80] = { 0,1,2,3,4,5,6,7,8,9 };
	//unsigned char * p = msg;
	//unsigned char* bufa1 = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	//unsigned char* bufa2 = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	//unsigned len1, len2;
	//pgp::Encrypt("d:\\pub_rsa.pem", msg, 80, bufa1, &len1);
	//for (int i = 0; i < len1; i++)
	//{
	//	printf("%d ", bufa1[i]);
	//}
	//printf("\n");
	//pgp::Decrypt("d:\\pri_rsa.pem", bufa1, len1, bufa2, &len2);
	//printf("%d\n", len2);
	//getchar();
	//for (int i = 0; i < len2; i++)
	//{
	//	printf("%d ", bufa2[i]);
	//}
	//printf("\n");
	return 0;
}

