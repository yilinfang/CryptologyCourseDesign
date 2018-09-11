// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "FormatExchange.h"
#include "string.h"
#include "spn_plus.h"
#include "rsa.h"
#include <openssl/bn.h>

using namespace std;


int main()
{
	rsa Rsa;
	Rsa.Generate();
	char s[] = "123abc";
	char* bufa;
	bufa = Rsa.Encrypt(s);
	printf("%s\n", bufa);
	char* bufa1;
	bufa1 = Rsa.Decrypt(bufa);
	printf("%s\n", bufa1);
}

