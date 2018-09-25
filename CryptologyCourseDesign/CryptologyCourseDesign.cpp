// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "spn_plus.h"
#include "rsa.h"
#include "pgp.h"
#include "rainbow.h"



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

	/*SPN_PLUS测试*/

	//unsigned char key0[16] = { 0 };
	//spn_plus spp(key0);
	//unsigned char msg[16] = { 0 };
	//FILE*  fp;
	//fopen_s(&fp, "D:\\data.txt", "wb");
	//for (int i = 0; i < 640000; i++)
	//{
	//	unsigned char * p = spp.Encrypt(msg);
	//	fwrite(p, 16 * sizeof(unsigned char), 1, fp);
	//}
	//fclose(fp);

	/*彩虹表测试*/
	rainbow r;
	r.CreateRainbowTable("d:\\rainbow_table.txt");
	//r.LoadRainbowTable("d:\\rainbow_table.txt");
	//unsigned char plain[maxsize + 1] = "wvutmf";
	//srand((unsigned)time(NULL));
	//unsigned char keymap[37] = "0123456789abcdefghijklmnopqrstuvwxyz";
	//for (int i = 0; i < 6; i++)
	//{
	//	plain[i] = keymap[rand() % 36];
	//}
	//plain[6] = 0;
	//printf("6位明文：%s\n", plain);
	//unsigned char* res = r.Hack(plain);
	//if (res)
	//{
	//	printf("明文串为：%s\n", res);
	//	free(res);
	//}
	//else
	//{
	//	printf("查表失败!\n");
	//}
	return 0;
}

