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
	rsa Rsa;
	Rsa.Generate();
	char s[] = "123abc";
	char *bufa1, *bufa2;
	bufa1 = Rsa.Encrypt(s);
	printf("%s\n", bufa1);
	bufa2 = Rsa.Decrypt(bufa1);
	printf("%s\n", bufa2);
	return 0;
}

