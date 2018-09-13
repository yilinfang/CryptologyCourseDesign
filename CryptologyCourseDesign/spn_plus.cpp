#include "spn_plus.h"


spn_plus::spn_plus(unsigned char * key0)
{
	KeyExpansion(key0);
	for (int i = 0; i < 128; i++)
	{
		pbox_inverse[pbox[i]] = i;
	}
	for (int i = 0; i < 256; i++)
	{
		sbox_inverse[sbox[i]] = i;
	}
;
}

unsigned char* spn_plus::Encrypt(unsigned char * plaintext)
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
	return plaintext;
}

unsigned char * spn_plus::Decrypt(unsigned char * ciphertext)
{
	int i = 10;
	ciphertext = Xor(ciphertext, key + i * 16);
	i--;
	ciphertext = Sub(ciphertext, sbox_inverse);
	ciphertext = Xor(ciphertext, key + i * 16);
	for (int i = 8; i >= 0; i--)
	{

		ciphertext = Per(ciphertext, pbox_inverse);
		ciphertext = Sub(ciphertext, sbox_inverse);
		ciphertext = Xor(ciphertext, key + i * 16);
	}
	return ciphertext;
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
		input[i] = sbox[input[i]];
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
	for (int i = 0; i < 128; i++)
	{
		unsigned char x = bufa[i / 8] & (0x80 >> (i % 8));
		unsigned char p = pbox[i];
		if (x)
		{
			input[p / 8] |= (0x80 >> (p  %  8));
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
