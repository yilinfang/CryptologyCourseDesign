#include "rainbow.h"



rainbow::rainbow()
{
	head = (unsigned char(*)[7]) malloc(sizeof(unsigned char) * round * 7);
	tail = (unsigned char(*)[7]) malloc(sizeof(unsigned char) * round * 7);
}


rainbow::~rainbow()
{
	free(head);
	free(tail);
}

void rainbow::CreateRainbowTable(const char * filepath)
{
	unsigned char encrypt0[maxsize + 1], encrypt[maxsize + 1], decrypt[16] = { 0 };
	FILE * fp = NULL;
	fopen_s(&fp, filepath, "at+");
	for (int i = 0; i < round; i++)
	{
		encrypt0[0] = PASSCHAR[5 + i / 100000 * 3];
		encrypt0[1] = PASSCHAR[4 + i / 10000 % 10 * 3];
		encrypt0[2] = PASSCHAR[3 + i / 1000 % 10 * 3];
		encrypt0[3] = PASSCHAR[2 + i / 100 % 10 * 3];
		encrypt0[4] = PASSCHAR[1 + i / 10 % 10 * 3];
		encrypt0[5] = PASSCHAR[0 + i % 10 * 3];
		encrypt0[6] = 0;
		CopyChar(encrypt0, encrypt, maxsize + 1);
		for (int j = 0; j < chainLength; j++)
		{
			MD5(encrypt, 6, decrypt);
			R7(encrypt, decrypt, j);
		}
		fprintf(fp, "%s %s\n", (char*)encrypt0, (char*)encrypt);
	}
}

void rainbow::LoadRainbowTable(const char * filepath)
{
	unsigned char _head[maxsize + 1], _tail[maxsize + 1];
	FILE * fp = NULL;
	fopen_s(&fp,filepath, "rt");
	int i = 0;
	if (fp)
	{
		while (fscanf(fp, "%s %s", _head, _tail) != EOF) 
		{
			CopyChar(_head, head[i], 6);
			CopyChar(_tail, tail[i], 6);
			i++;
		}
		fclose(fp);
	}
}

unsigned char* rainbow::Hack(unsigned char * plain)
{
	int matchMark;
	bool flag;
	unsigned char encrypt[maxsize + 1], hash_md5[16], hash_md5_0[16];
	unsigned char* breaker_md5 = (unsigned char*)malloc((maxsize + 1) * sizeof(unsigned char));
	MD5(plain, 6, hash_md5);
	CopyChar(hash_md5, hash_md5_0, 16);
	breaker_md5[6] = 0;
	for (int i = chainLength - 1; i >= 0; i--)
	{
		for (int j = i; j < chainLength - 1; j++)
		{
			R7(encrypt, hash_md5, j);
			MD5(encrypt, 6, hash_md5);
		}
		R7(encrypt, hash_md5, chainLength - 1);
		matchMark = Match(encrypt);
		flag = Verify(matchMark, hash_md5_0, breaker_md5, i);
		if (flag)
		{
			if (matchMark != 1000000)
			{
				break;
			}
		}
		else
		{
			CopyChar(hash_md5_0, hash_md5, 16);
		}
	}
	if (flag)
	{
		return breaker_md5;
	}
	else
	{
		free(breaker_md5);
		return NULL;
	}
}

void rainbow::R7(unsigned char * pwd, unsigned char * hash, int step)
{

	uint32_t idx[4];

	idx[0] = (*(uint32_t*)hash) ^ step;
	idx[1] = (*(uint32_t*)(hash + 4));
	idx[2] = (*(uint32_t*)(hash + 8));
	idx[3] = (*(uint32_t*)(hash + 12));


	idx[0] %= len * len;
	idx[1] %= len * len;
	idx[2] %= len * len;
	idx[3] %= len * len;
	pwd[0] = PASSCHAR[idx[0] / len];
	pwd[1] = PASSCHAR[idx[1] % len];
	pwd[2] = PASSCHAR[idx[1] / len];
	pwd[3] = PASSCHAR[idx[2] % len];
	pwd[4] = PASSCHAR[idx[2] / len];
	pwd[5] = PASSCHAR[idx[3] % len];


	pwd[6] = 0;
}

void rainbow::CopyChar(unsigned char * input, unsigned char * output, int length)
{
	for (int i = 0; i < length; i++)
	{
		output[i] = input[i];
	}
}

bool rainbow::Verify(int index, unsigned char * hash, unsigned char * breaker, int N)
{
	unsigned char encrypt[maxsize + 1], decrypt[16];
	CopyChar(head[index], encrypt, maxsize);
	for (int i = 0; i < N; i++)
	{
		MD5(encrypt, 6, decrypt);
		R7(encrypt, decrypt, i);
	}
	CopyChar(encrypt, breaker, 6);
	MD5(encrypt, 6, decrypt);
	if (Compare(decrypt, hash, 16))
		return true;
	else
		return false;
}

bool rainbow::Compare(unsigned char * a, unsigned char * b, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (a[i] != b[i])
		{
			return false;
		}
	}
	return true;
}

int rainbow::Match(unsigned char * p)
{
	int i, j;
	for (i = 0; i < round; i++)
	{
		for (j = 0; j < 6; j++)
		{
			if (p[j] != tail[i][j])
			{
				break;
			}
		}
		if (j == 6)
		{
			return i;
		}
	}
	return 1000000;
}
