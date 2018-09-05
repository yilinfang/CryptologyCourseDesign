#include "FormatExchange.h"

Plaintext String2Plaintext(char* s, int len)
{
	Plaintext plaintext;
	plaintext.len_f = len;
	if ((plaintext.len_f % 2) != 0)
	{
		len++;
	}
	plaintext.bufa = (unsigned char*)malloc(len * sizeof(unsigned char));
	plaintext.len = len;
	memcpy(plaintext.bufa, s, len * sizeof(unsigned char));
	return plaintext;
}

char* Plaintext2String(Plaintext text)
{
	char* str = (char*)malloc((text.len_f + 1) * sizeof(char));
	memcpy(str, text.bufa, text.len_f * sizeof(char));
	str[text.len_f] = '\0';
	return str;
}

bool * UnsignedChar_A2Bool_A(unsigned char x[], int len)
{
	bool* bufa = (bool*)malloc(len * 8 * sizeof(bool));
	unsigned char w = 0x80;
	for (int i = 0; i < len; i++)
	{
		w = 0x80;
		for (int j = 0; j < 8; j++)
		{
			if (x[i] & w)
			{
				bufa[8 * i + j] = true;
			}
			else
			{
				bufa[8 * i + j] = false;
			}
			w /= 2;
		}
	}
	return bufa;
}

unsigned char * Bool_A2UnsignedChar_A(bool x[], int len)
{
	unsigned char* bufa = (unsigned char*)malloc(len * sizeof(unsigned char) / 8);
	unsigned char w, n;
	w = 0x80;
	n = 0;
	for (int i = 0; i < len / 8; i++)
	{
		unsigned char w, n;
		w = 0x80;
		n = 0;
		for (int j = 0; j < 8; j++)
		{
			if (x[8 * i + j])
			{
				n += w;
			}
			w /= 2;
		}
		bufa[i] = n;
	}
	return bufa;
}

void InitCiphertext(Plaintext plaintext, Ciphertext &ciphertext)
{
	ciphertext.len = plaintext.len;
	ciphertext.len_f = plaintext.len_f;
	ciphertext.bufa = (unsigned char*)malloc(ciphertext.len * sizeof(unsigned char));
	memcpy(ciphertext.bufa, plaintext.bufa, ciphertext.len * sizeof(unsigned char));
}

void InitPlaintext(Plaintext &plaintext, Ciphertext ciphertext)
{
	plaintext.len = ciphertext.len;
	plaintext.len_f = ciphertext.len_f;
	plaintext.bufa = (unsigned char*)malloc(plaintext.len * sizeof(unsigned char));
	memcpy(plaintext.bufa, ciphertext.bufa, plaintext.len * sizeof(unsigned char));
}

void DestroyPlaintext(Plaintext &plaintext)
{
	free(plaintext.bufa);
	plaintext.len = plaintext.len_f = 0;
}

void DestroyCiphertext(Ciphertext &ciphertext)
{
	ciphertext.len_f = ciphertext.len = 0;
	free(ciphertext.bufa);
}
