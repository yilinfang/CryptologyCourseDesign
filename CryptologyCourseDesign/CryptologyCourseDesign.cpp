// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "spn_plus.h"
#include "rsa.h"
#include "pgp.h"
#include "rainbow.h"
#include "FormatExchange.h"
#include <time.h>



int main()
{
	/*SPN测试*/

	//Ciphertext cipher;
	//unsigned char _key[4] = { 0x3A,0x94,0xD6,0x3F };
	//unsigned char* key = (unsigned char*)malloc(4 * sizeof(unsigned char));
	//memcpy(key, _key, 4 * sizeof(unsigned char));
	//char _str[] = "HelloWorld!";
	//int len = strlen(_str);
	//char* bufa = (char*)malloc(100 * sizeof(char));
	//strcpy(bufa, _str);
	//printf("加密前:%s", bufa);
	//spn s(key);
	//cipher = s.Encrypt(bufa, len);
	//char* bufa2 = Ciphertext2String(cipher);
	//printf("\n加密后:%s", bufa2);
	//char* bufa3 = s.Decrypt(cipher);
	//printf("\n解密后:%s", bufa3);
	//free(key);
	//free(bufa);
	//free(bufa2);
	//free(bufa3);
	//DestroyCiphertext(cipher);
	////线性攻击
	//bool(*x)[16];
	//bool(*y)[16];
	//x = (bool(*)[16]) malloc(sizeof(bool) * 10000 * 16);
	//y = (bool(*)[16]) malloc(sizeof(bool) * 10000 * 16);
	//s.CreateAttackTestData("d:\\x.txt", x, "d:\\y.txt", y, 10000);
	//s.LoadAttackTestData("d:\\x.txt", "d:\\y.txt", x, y, 10000);
	//float start, end;
	//start = clock();
	//bool* bufa4 = s.LinearAttack(x, y, 10000);
	//end = clock();
	//printf("\n线性攻击结果(耗时:%fs):",(end - start)/ CLOCKS_PER_SEC);
	//for (int i = 0; i < 8; i++)
	//{
	//	printf("%d ", bufa4[i]);
	//}
	//start = clock();
	//bool* bufa5 = s.ViolateAttack(x, y, bufa4, 10000);
	//end = clock();
	//printf("\n暴力破解剩余24位(耗时%fs):",(end - start) / CLOCKS_PER_SEC);
	//for (int i = 0; i < 32; i++)
	//{
	//	printf("%d ", bufa5[i]);
	//}
	//free(bufa4);
	//free(bufa5);
	////差分攻击
	//start = clock();
	//bool* bufa6 = s.DifferAttack(x, y, 10000);
	//end = clock();
	/*printf("\n差分攻击结果(耗时:%fs):", (end - start) / CLOCKS_PER_SEC);
	for (int i = 0; i < 8; i++)
	{
		printf("%d ", bufa6[i]);
	}
	start = clock();
	bool* bufa7 = s.ViolateAttack(x, y, bufa6, 10000);
	end = clock();
	printf("\n暴力破解剩余24位(耗时%fs):", (end - start) / CLOCKS_PER_SEC);
	for (int i = 0; i < 32; i++)
	{
		printf("%d ", bufa7[i]);
	}
	free(bufa6);
	free(bufa7);
	free(x);
	free(y);*/

	/*RSA测试*/

	//rsa Rsa;
	//float start, end;
	//Rsa.Generate();
	//char msg[] = "123ABC";
	//char* bufa2, * bufa1 = Rsa.Encrypt(msg);
	//printf("%s\n", bufa1);

	//start = clock();
	//bufa2 = Rsa.Decrypt(bufa1);
	//end = clock();
	//printf("%s exp sec:%f\n", bufa2, (end - start) / CLOCKS_PER_SEC);
	//OPENSSL_free(bufa2);

	//start = clock();
	//bufa2 = Rsa.Decrypt_mont(bufa1);
	//end = clock();
	//printf("%s mont sec:%f\n", bufa2, (end - start) / CLOCKS_PER_SEC);
	//OPENSSL_free(bufa2);

	//start = clock();
	//bufa2 = Rsa.Decrypt_reminder(bufa1);
	//end = clock();
	//printf("%s reminder sec:%f\n", bufa2, (end - start) / CLOCKS_PER_SEC);
	//OPENSSL_free(bufa2);

	//OPENSSL_free(bufa1);

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

	///*彩虹表测试*/
	//rainbow r;
	////r.CreateRainbowTable("d:\\rainbow_table.txt");
	//r.LoadRainbowTable("d:\\rainbow_table.txt");
	//unsigned char plain[maxsize + 1] = "wvutmf";
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
	//srand((unsigned)time(NULL));
	//unsigned char keymap[37] = "0123456789abcdefghijklmnopqrstuvwxyz";
	//int hit = 0;
	//for (int j = 0; j < 20; j++)
	//{
	//	for (int i = 0; i < 6; i++)
	//	{
	//		plain[i] = keymap[rand() % 36];
	//	}
	//	plain[6] = 0;
	//	printf("6位明文：%s\n", plain);
	//	unsigned char* res = r.Hack(plain);
	//	if (res)
	//	{
	//		printf("明文串为：%s\n", res);
	//		hit++;
	//		free(res);
	//	}
	//	else
	//	{
	//		printf("查表失败!\n");
	//	}
	//}
	//printf("命中率:%f\n", hit / 20);
	return 0;
}

