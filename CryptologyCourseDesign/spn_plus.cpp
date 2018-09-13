#include "spn_plus.h"


spn_plus::spn_plus(unsigned char * key0)
{
	KeyExpansion(key0);
}

void spn_plus::Encrypt(unsigned char * plaintext)
{
	int i;
	for (i = 0; i < 9; i++)
	{
		plaintext = Xor(plaintext, key + i * 16);
		plaintext = Sub(plaintext, sbox);
		plaintext = Per(plaintext, pbox);
	}
	plaintext = Xor(plaintext, key + i * 16);
	plaintext = Sub(plaintext, sbox);
	i++;
	plaintext = Xor(plaintext, key + i * 16);
}

unsigned char * spn_plus::Xor(unsigned char * a, unsigned char * b)
{
	for (int i = 0; i < 16; i++)
	{
		a[i] = a[i] ^ b[i];
	}
	return a;
}

unsigned char * spn_plus::Sub(unsigned char * input, unsigned char * sbox)
{
	for (int i = 0; i < 16; i++)
	{
		unsigned char x, y;
		x = input[i] >> 4;
		y = input[i] & 0xf;
		input[i] = sbox[16 * x + y];
	}
	return input;
}

unsigned char * spn_plus::Per(unsigned char * input, unsigned char * pbox)
{
	unsigned char bufa[17] = {0};
	for (int i = 0; i < 16; i++)
	{
		bufa[i] = input[i];
		input[i] = 0;
	}
	for (int i = 0; i < 16; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			unsigned char a, b, c, t;
			a = pbox[i * 8 + j];
			b = a / 8;
			c = a % 8;
			t = ((bufa[i] >> (7 - j)) & 0x1) << (7 - c);
			input[b] = input[b] | t;
		}
	}
	return input;
}

void spn_plus::RotWord(unsigned char * input)
{
	unsigned char t = input[0];
	input[0] = input[1];
	input[1] = input[2];
	input[2] = input[3];
	input[3] = t;
}

void spn_plus::KeyExpansion(unsigned char * key0)
{
	unsigned char RCon[10] = { 0x10 , 0x20 , 0x40 , 0x80 , 0x10 , 0x20 ,0x40 , 0x80 , 0x1b, 0x36 };
	int i, j, k;
	unsigned char temp[4], x, y;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			key[0 * 16 + i * 4 + j] = key0[i * 4 + j];
		}

	}
	for (i = 1; i < 11; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				if (j == 0)
					temp[k] = key[(i - 1) * 16 + 12 + k];
				else temp[k] = key[i * 16 + (j - 1) * 4 + k];
			}
			if (j == 0)
			{
				RotWord(temp);
				for (k = 0; k < 4; k++)
				{
					x = temp[k] >> 4;
					y = temp[k] & 0xf;
					temp[k] = sbox[x * 16 + y];
					if (k == 0)
						temp[k] = temp[k] ^ RCon[i - 1];
				}
			}
			for (k = 0; k < 4; k++)
				key[i * 16 + j * 4 + k] = key[(i - 1) * 16 + j * 4 + k] ^ temp[k];
		}
	}
}
