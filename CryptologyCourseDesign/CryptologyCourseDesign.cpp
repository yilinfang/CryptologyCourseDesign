// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "FormatExchange.h"
#include "string.h"

#define TESTNUM 10000

int main()
{
	unsigned char key[4] = { 0x3A, 0x94, 0xD6, 0x3F };
	spn Spn(key);

	bool x[TESTNUM][16];
	bool y[TESTNUM][16];
	Spn.CreateAttackTestData("D:\\x.txt", x, "D:\\y.txt", y, TESTNUM);
	//bool* bufa = Spn.LinearAttack(x, y, TESTNUM);
	bool* bufa = Spn.DifferAttack(x, y, TESTNUM);
	printf("\n差分攻击结果:");
	for (int i = 0; i < 8; i++)
	{
		printf("%d ", bufa[i]);
	}
	getchar();
	bool* bufa2 = Spn.ViolateAttack(x, y, bufa, TESTNUM);
	printf("\n穷举结果:");
	if (!bufa2)
	{
		printf("\n攻击失败，未找到正确密钥！");
		getchar();
		return 0;
	}
	for (int i = 0; i < 32; i++)
	{
		printf("%d ", bufa2[i]);
	}
	printf("\n");
	getchar();
	return 0;
}

