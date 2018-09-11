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
	//char str[] = "HelloWorld";
	//unsigned char *s;
	//s = (unsigned char*)malloc(strlen(str) * sizeof(unsigned char));
	//memcpy(s, str, strlen(str) * sizeof(unsigned char));
	//rsa Rsa;
	//Rsa.Generate();
	//char* bufa;
	//Rsa.Encrypt(s, strlen(str), bufa);
	//printf("%s\n", bufa);
	//int len;
	//unsigned char* bufa1;
	//bufa1 = (unsigned char*)malloc(1000 * sizeof(unsigned char));
	//Rsa.Decrypt(bufa, bufa1, len);
	//char* bufa2;
	//bufa2 = (char*)malloc(sizeof(char) * (len + 1));
	//bufa2[len] = '\0';
	//memcpy(bufa2, bufa1, len * sizeof(char));
	//printf("%s\n", bufa2);
	//return 0;
	char msg[] = "abcdefghijklmnopq";
	unsigned char bufa[1000] = { 0 };
	unsigned char bufa1[1000] = { 0 };
	unsigned int len;
	pgp::CreateECKeys("d:\\pub_ec.pem", "d:\\pri_ec.pem");
	pgp::Digest(msg, strlen(msg), bufa, &len);
	printf("%d\n", len);
	for (int i = 0; i < len; i++)
	{
		printf("%d ", bufa[i]);
	}
	pgp::Signature("d:\\pri_ec.pem", bufa, 20, bufa1, &len);
	printf("\n%d\n", len);
	for (int i = 0; i < len; i++)
	{
		printf("%d ", bufa1[i]);
	}
	int n = pgp::Verify("d:\\pub_ec.pem", bufa, 20, bufa1, len);
	printf("\n%d\n", n);
	pgp::CreateRSAKeys("d:\\pub_rsa.pem", "d:\\pri_rsa.pem");
	return 0;
}

