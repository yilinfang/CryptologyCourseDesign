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

	/*RSA测试*/


	//rsa Rsa;
	//Rsa.Generate();
	//char msg[] = "123ABC";
	//char* bufa1 = Rsa.Encrypt(msg);
	//printf("%s\n", bufa1);
	//char* bufa2 = Rsa.Decrypt(bufa1);
	//printf("%s\n", bufa2);
	//OPENSSL_free(bufa1);
	//OPENSSL_free(bufa2);

	/*PGP测试*/
	//char s[] = "123abcd";
	//pgp::Encrypt(s, "d:\\pub_rsa.pem", "d:\\pri_ec.pem", "d:\\input.txt", "d:\\output1.txt");
	//int i = pgp::Decrypt("d:\\pub_ec.pem", "d:\\pri_rsa.pem", "d:\\output1.txt", "d:\\output2.txt");
	//printf("%d\n", i);

	unsigned char key0[16] = { 0 };
	spn_plus spp(key0);
	unsigned char msg[16] = { 0 };
	FILE*  fp;
	fopen_s(&fp, "D:\\data.txt", "wb");
	for (int i = 0; i < 640000; i++)
	{
		unsigned char * p = spp.Encrypt(msg);
		fwrite(p, 16 * sizeof(unsigned char), 1, fp);
	}
	fclose(fp);
	return 0;
}

