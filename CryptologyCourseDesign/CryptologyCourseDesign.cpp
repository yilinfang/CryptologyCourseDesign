// CryptologyCourseDesign.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "spn.h"
#include "FormatExchange.h"
#include "string.h"
#include <ctime>

int main()
{
	unsigned char key[4] = { 0x00, 0x04, 0xD6, 0x3F };
	spn Spn(key);

	//srand((unsigned)time(NULL));
	//FILE* f1, *f2;
	//fopen_s(&f1, "D:\\x.txt", "w");
	//fopen_s(&f2, "D:\\y.txt", "w");
	//for (int i = 0; i < 10000; i++)
	//{
	//	unsigned char bufa[2];
	//	bufa[0] = rand() & 0xff;
	//	bufa[1] = rand() & 0xff;
	//	printf("%d %d\n", bufa[0], bufa[1]);
	//	bool* bufa1 = UnsignedChar_A2Bool_A(bufa, 2);
	//	for (int j = 0; j < 16; j++)
	//	{
	//		fprintf(f1, "%d ", (bufa1[j] && 1));
	//	}
	//	fprintf(f1, "\n");
	//	Spn.Encrypt(bufa1);
	//	for (int j = 0; j < 16; j++)
	//	{
	//		fprintf(f2, "%d ", (bufa1[j] && 1));
	//	}
	//	fprintf(f2, "\n");
	//}
	//fclose(f1);
	//fclose(f2);

	FILE* f1, *f2;
	fopen_s(&f1, "D:\\x.txt", "r");
	fopen_s(&f2, "D:\\y.txt", "r");
	bool x[10000][16];
	bool y[10000][16];
	for (int i = 0; i < 10000; i++)
	{
		printf("\nx:");
		for (int j = 0; j < 16; j++)
		{
			int tmp = 0;
			fscanf_s(f1, "%d", &tmp);
			printf(" %d", tmp);
			if (tmp)
			{
				x[i][j] = 1;
			}
			else
			{
				x[i][j] = 0;
			}
		}
		printf("\ny:");
		for (int j = 0; j < 16; j++)
		{
			int tmp = 0;
			fscanf_s(f2, "%d", &tmp);
			printf(" %d", tmp);
			if (tmp)
			{
				y[i][j] = 1;
			}
			else
			{
				y[i][j] = 0;
			}
		}
	}
	fclose(f1);
	fclose(f2);
	
	bool* bufa = Spn.LinearAttack(x, y, 10000);
	printf("\n线性攻击结果:");
	for (int i = 0; i < 8; i++)
	{
		printf("%d ", bufa[i]);
	}
	getchar();
	bool* bufa2 = Spn.ViolateAttack(x, y, bufa, 10000);
	printf("\n穷举结果:");
	if (!bufa2)
	{
		printf("\n查找失败!");
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

