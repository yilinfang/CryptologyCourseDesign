#include "spn_plus.h"


spn_plus::spn_plus(unsigned char * _key)
{
	bool* bufa = UnsignedChar_A2Bool_A(_key, 16);
	memcpy(key, bufa, 128 * sizeof(bool));
	free(bufa);
	CreateLocalkey();
}

spn_plus::~spn_plus()
{
}

Ciphertext spn_plus::Encrypt(char * str, int len)
{
	Plaintext plaintext = String2Plaintext(str, len, 128);
	Ciphertext ciphertext;
	ciphertext.len = ciphertext.len_f = 0;
	ciphertext.bufa = NULL;
	this->Encrypt(plaintext, ciphertext);
	DestroyPlaintext(plaintext);
	return ciphertext;
}

void spn_plus::Encrypt(Plaintext plaintext, Ciphertext & ciphertext)
{
	InitCiphertext(plaintext, ciphertext);
	int len = ciphertext.len / 16;
	for (int i = 0; i < len; i++)
	{
		bool* bufa1 = UnsignedChar_A2Bool_A(ciphertext.bufa + 16 * i, 16);
		this->Encrypt(bufa1);
		unsigned char* bufa2 = Bool_A2UnsignedChar_A(bufa1, 128);
		memcpy(ciphertext.bufa + 16 * i, bufa2, 16 * sizeof(unsigned char));
		free(bufa1);
		free(bufa2);
	}
}

void spn_plus::Encrypt(bool * text)
{
	for (int i = 0; i < 8; i++)
	{
		Xor(localKey[i], text, 128);
		SReplacement(text, sbox[i], 128);
		PReplacement(text, pbox, 128);
	}
	Xor(localKey[8], text, 16);
	SReplacement(text, sbox[9], 128);
	Xor(localKey[9], text, 16);
}

void spn_plus::ResetSbox(int box_num, int box_size)
{
	srand(unsigned(time(NULL)));
	int Max = 1;
	for (int i = 1; i < box_size; i++)
	{
		Max <<= 1;
	}
	for (int i = 0; i < box_num; i++)
	{
		int count = 0;
		int key_map[1000] = { 0 };
		while (count <= Max)
		{
			int n = rand() % (Max + 1);
			if (!key_map[n])
			{
				key_map[n] = 1;
				sbox[box_num][count] = n;
				count++;
			}
		}
	}
}

void spn_plus::ResetPbox(int box_num, int box_size)
{
	srand(unsigned(time(NULL)));
	int Max = 1;
	for (int i = 1; i < box_size; i++)
	{
		Max <<= 1;
	}
	for (int i = 0; i < box_num; i++)
	{
		int count = 0;
		int key_map[1000] = { 0 };
		while (count <= Max)
		{
			int n = rand() % (Max + 1);
			if (!key_map[n + 1])
			{
				key_map[n + 1] = 1;
				sbox[box_num][count] = n + 1;
				count++;
			}
		}
	}
}

bool spn_plus::Xor(bool x, bool y)
{
	return x ^ y;
}

void spn_plus::Xor(bool x[], bool y[], int len)
{
	for (int i = 0; i < len; i++)
	{
		y[i] = Xor(x[i], y[i]);
	}
}

void spn_plus::Xor(bool x[], bool y[], bool z[], int len)
{
	for (int i = 0; i < len; i++)
	{
		z[i] = Xor(x[i], y[i]);
	}
}

void spn_plus::CreateLocalkey()
{
	for (int i = 0; i < 10; i++)
	{
		bool bufa[128] = { 0 };
		memcpy(bufa, key + 8 * i, (128 - 8 * i) * sizeof(bool));
		memcpy(bufa + (128 - 8 * i), key, 8 * i * sizeof(bool));
		memcpy(localKey[i], bufa, 128 * sizeof(bool));
	}
}

void spn_plus::SReplacement(bool * u, int * s, int s_len)
{
	int s_num = 128 / s_len;
	int weight = 1;
	for (int i = 1; i < s_len; i++)
	{
		weight <<= 1;
	}
	for (int i = 0; i < s_num; i++)
	{
		int w = weight;
		int n = 0;
		for (int j = 0; j < s_len; j++)
		{
			if (u[s_len * i + j])
			{
				n += weight;
			}
			weight >>= 2;
		}
		n = s[n];
		for (int j = 0; j < s_len; j++)
		{
			u[s_len * i + j] = (n >> (s_len - j - 1)) & 0xff;
		}
	}
}

void spn_plus::PReplacement(bool * v, int * p, int s_len)
{
	int s_num = 128 / s_len;
	for (int i = 0; i < s_num; i++)
	{
		bool* bufa = (bool*)malloc(s_len * sizeof(bool));
		for (int j = 0; j < s_len; j++)
		{
			bufa[j] = v[s_len * i + p[j] - 1];
		}
		memcpy(v + s_len * i, bufa, s_len * sizeof(bool));
		free(bufa);
	}
}
