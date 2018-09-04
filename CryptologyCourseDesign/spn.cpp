#include "stdafx.h"
#include "spn.h"


spn::spn(unsigned char * _key)
{
	bool* bufa = UnsignedChar_A2Bool_A(_key, 4);
	memcpy(key, bufa, 32 * sizeof(bool));
	free(bufa);
	CreateLocalkey();
}


spn::~spn()
{
}

Ciphertext spn::Encrypt(char * str, int len)
{
	Plaintext plaintext = String2Plaintext(str, len);
	Ciphertext ciphertext;
	ciphertext.len = ciphertext.len_f = 0;
	ciphertext.bufa = NULL;
	this->Encrypt(plaintext, ciphertext);
	DestroyPlaintext(plaintext);
	return ciphertext;
}

void spn::Encrypt(Plaintext plaintext, Ciphertext &ciphertext)
{
	InitCiphertext(plaintext, ciphertext);
	int len = ciphertext.len / 2;
	for (int i = 0; i < len; i++)
	{
		bool* bufa1 = UnsignedChar_A2Bool_A(ciphertext.bufa + 2 * i, 2);
		this->Encrypt(bufa1);
		unsigned char* bufa2 = Bool_A2UnsignedChar_A(bufa1, 16);
		memcpy(ciphertext.bufa + 2 * i, bufa2, 2 * sizeof(unsigned char));
		free(bufa1);
		free(bufa2);
	}
}

void spn::Encrypt(bool* text)
{
	for (int i = 0; i < 3; i++)
	{
		Xor(localKey[i], text, 16);
		SReplacement(text);
		PReplacement(text);
	}
	Xor(localKey[3], text, 16);
	SReplacement(text);
	Xor(localKey[4], text, 16);
}

char * spn::Decrypt(Ciphertext ciphertext)
{
	Plaintext plaintext;
	plaintext.len = plaintext.len_f = 0;
	plaintext.bufa = NULL;
	this->Decrypt(plaintext, ciphertext);
	char* bufa = Plaintext2String(plaintext);
	DestroyPlaintext(plaintext);
	return bufa;
}

void spn::Decrypt(Plaintext &plaintext, Ciphertext ciphertext)
{
	InitPlaintext(plaintext, ciphertext);
	int len = plaintext.len / 2;
	for (int i = 0; i < len; i++)
	{
		bool* bufa1 = UnsignedChar_A2Bool_A(plaintext.bufa + 2 * i, 2);
		this->Decrypt(bufa1);
		unsigned char* bufa2 = Bool_A2UnsignedChar_A(bufa1, 16);
		memcpy(plaintext.bufa + 2 * i, bufa2, 2 * sizeof(unsigned char));
		free(bufa1);
		free(bufa2);
	}
}

void spn::Decrypt(bool * text)
{
	Xor(localKey[4], text, 16);
	SReplacement_R(text);
	Xor(localKey[3], text, 16);
	for (int i = 2; i >= 0; i--)
	{
		PReplacement_R(text);
		SReplacement_R(text);
		Xor(localKey[i], text, 16);
	}
}

unsigned char * spn::GetKey()
{
	return Bool_A2UnsignedChar_A(key, 32);
}

void spn::CreateAttackTestData(const char * x_filename,const char * y_filename, int num)
{
	srand((unsigned)time(NULL));
	FILE* f1, *f2;
	fopen_s(&f1, x_filename, "w");
	fopen_s(&f2, y_filename, "w");
	for (int i = 0; i < num; i++)
	{
		unsigned char bufa[2];
		bufa[0] = rand() & 0xff;
		bufa[1] = rand() & 0xff;
		bool* bufa1 = UnsignedChar_A2Bool_A(bufa, 2);
		for (int j = 0; j < 16; j++)
		{
			fprintf(f1, "%d ", (bufa1[j] && 1));
		}
		fprintf(f1, "\n");
		this->Encrypt(bufa1);
		for (int j = 0; j < 16; j++)
		{
			fprintf(f2, "%d ", (bufa1[j] && 1));
		}
		fprintf(f2, "\n");
		free(bufa1);
	}
	fclose(f1);
	fclose(f2);
}

void spn::CreateAttackTestData(bool x[][16], bool y[][16], int num)
{
	srand((unsigned)time(NULL));
	for (int i = 0; i < num; i++)
	{
		unsigned char bufa[2];
		bufa[0] = rand() & 0xff;
		bufa[1] = rand() & 0xff;
		bool* bufa1 = UnsignedChar_A2Bool_A(bufa, 2);
		memcpy(x[i], bufa1, 16 * sizeof(bool));
		this->Encrypt(bufa1);
		memcpy(y[i], bufa1, 16 * sizeof(bool));
		free(bufa1);
	}
}

void spn::CreateAttackTestData(const char * x_filename, bool x[][16], const char * y_filename, bool y[][16], int num)
{
	srand((unsigned)time(NULL));
	FILE* f1, *f2;
	fopen_s(&f1, x_filename, "w");
	fopen_s(&f2, y_filename, "w");
	for (int i = 0; i < num; i++)
	{
		unsigned char bufa[2];
		bufa[0] = rand() & 0xff;
		bufa[1] = rand() & 0xff;
		bool* bufa1 = UnsignedChar_A2Bool_A(bufa, 2);
		for (int j = 0; j < 16; j++)
		{
			fprintf(f1, "%d ", (bufa1[j] && 1));
		}
		fprintf(f1, "\n");
		memcpy(x[i], bufa1, 16 * sizeof(bool));
		this->Encrypt(bufa1);
		for (int j = 0; j < 16; j++)
		{
			fprintf(f2, "%d ", (bufa1[j] && 1));
		}
		fprintf(f2, "\n");
		memcpy(y[i], bufa1, 16 * sizeof(bool));
		free(bufa1);
	}
	fclose(f1);
	fclose(f2);
}

void spn::LoadAttackTestData(const char * x_filename, const char * y_filename, bool x[][16], bool y[][16], int num)
{
	FILE* f1, *f2;
	fopen_s(&f1, x_filename, "r");
	fopen_s(&f2, y_filename, "r");
	for (int i = 0; i < num; i++)
	{
		for (int j = 0; j < 16; j++)
		{
			int tmp = 0;
			fscanf_s(f1, "%d", &tmp);
			if (tmp)
			{
				x[i][j] = 1;
			}
			else
			{
				x[i][j] = 0;
			}
		}
		for (int j = 0; j < 16; j++)
		{
			int tmp = 0;
			fscanf_s(f2, "%d", &tmp);
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
}

bool * spn::LinearAttack(bool x[][16], bool y[][16], int num)
{
	int count[256] = { 0 };
	int max = 0;
	int maxNum = 0;
	bool key[256][8];
	for (int i = 0; i < 256; i++)
	{
		unsigned char temp = i & 0xff;
		bool* bufa = UnsignedChar_A2Bool_A(&temp, 1);
		memcpy(key[i], bufa, 8 * sizeof(bool));
		free(bufa);
	}
	for (int i = 0; i < 256; i++)
	{
		count[i] = LinearAttack(x, y, num, key[i]);
	}
	for (int i = 0; i < 256; i++)
	{
		if (abs(count[i] - num / 2) > max)
		{
			max = abs(count[i] - num / 2);
			maxNum = i;
		}
	}
	bool* bufa = (bool*)malloc(8 * sizeof(bool));
	memcpy(bufa, key[maxNum], 8 * sizeof(bool));
	return bufa;
}

int spn::LinearAttack(bool x[][16], bool y[][16], int num, bool * _key)
{
	bool key[16] = { 0 };
	memcpy(key + 4, _key, 4 * sizeof(bool));
	memcpy(key + 12, _key + 4, 4 * sizeof(bool));
	int count = 0;
	bool v[16];
	bool z;
	for (int i = 0; i < num; i++)
	{
		Xor(key, y[i], v, 16);
		SReplacement_R(v);
		z = x[i][4] ^ x[i][6] ^ x[i][7] ^ v[5] ^ v[7] ^ v[13] ^ v[15];
		if (!z)
		{
			count++;
		}
	}
	return count;
}

bool * spn::ViolateAttack(bool x[][16], bool y[][16], bool key[8], int num)
{
	unsigned char key_t[3] = {0};
	bool * bufa1 = (bool*)malloc(32 * sizeof(bool));
	for (int i = 0; i < 0xffffff; i++)
	{ 
		key_t[0] = (i >> 16) & 0x0000ff;
		key_t[1] = (i >> 8) & 0x0000ff;
		key_t[2] = i & 0x0000ff;
		bool * bufa2 = UnsignedChar_A2Bool_A(key_t, 3);
		memcpy(bufa1, bufa2, 20 * sizeof(bool));
		memcpy(bufa1 + 20, key, 4 * sizeof(bool));
		memcpy(bufa1 + 24, bufa2 + 20, 4 * sizeof(bool));
		memcpy(bufa1 + 28, key + 4, 4 * sizeof(bool));
		if (IsRightKey(x, y, num, bufa1))
		{
			free(bufa2);
			return bufa1;
		}
		free(bufa2);
	}
	free(bufa1);
	return NULL;
}



bool spn::Xor(bool x, bool y)
{
	if (x != y)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void spn::Xor(bool x[], bool y[], int len)
{
	for (int i = 0; i < len; i++)
	{
		y[i] = Xor(x[i], y[i]);
	}
}

void spn::Xor(bool x[], bool y[], bool z[], int len)
{
	for (int i = 0; i < len; i++)
	{
		z[i] = Xor(x[i], y[i]);
	}
}

void spn::CreateLocalkey()
{
	memcpy(localKey[0], key, 16 * sizeof(bool));
	memcpy(localKey[1], key + 4, 16 * sizeof(bool));
	memcpy(localKey[2], key + 8, 16 * sizeof(bool));
	memcpy(localKey[3], key + 12, 16 * sizeof(bool));
	memcpy(localKey[4], key + 16, 16 * sizeof(bool));
}

void spn::SReplacement(bool* u)
{
	bool tmpBool[16];
	int tmp1, tmp2;
	for (int i = 0; i < 16; i += 4) {
		tmp1 = 8 * u[i] + 4 * u[i + 1] + 2 * u[i + 2] + u[i + 3];
		tmp2 = sbox[tmp1];
		tmpBool[i] = (tmp2 >> 3) & 0x01;
		tmpBool[i + 1] = (tmp2 >> 2) & 0x01;
		tmpBool[i + 2] = (tmp2 >> 1) & 0x01;
		tmpBool[i + 3] = tmp2 & 0x01;
	}
	memcpy(u, tmpBool, 16 * sizeof(bool));
	return;
}

void spn::SReplacement_R(bool* u)
{
	bool tmpBool[16];
	int tmp1, tmp2;
	for (int i = 0; i < 16; i += 4) {
		tmp1 = 8 * u[i] + 4 * u[i + 1] + 2 * u[i + 2] + u[i + 3];
		tmp2 = sbox_r[tmp1];
		tmpBool[i] = (tmp2 >> 3) & 0x01;
		tmpBool[i + 1] = (tmp2 >> 2) & 0x01;
		tmpBool[i + 2] = (tmp2 >> 1) & 0x01;
		tmpBool[i + 3] = tmp2 & 0x01;
	}
	memcpy(u, tmpBool, 16 * sizeof(bool));
	return;
}


void spn::PReplacement(bool* v)
{
	bool tmpBool[16];
	for (int i = 0; i < 16; i++) {
		tmpBool[i] = v[pbox[i] - 1];
	}
	memcpy(v, tmpBool, 16 * sizeof(bool));
	return;
}

void spn::PReplacement_R(bool * v)
{
	bool tmpBool[16];
	for (int i = 0; i < 16; i++) {
		tmpBool[i] = v[pbox_r[i] - 1];
	}
	memcpy(v, tmpBool, 16 * sizeof(bool));
	return;
}

bool spn::IsRightKey(bool x[][16], bool y[][16], int num, bool * key)
{
	for (int i = 0; i < num; i++)
	{
		bool test[16];
		memcpy(test, x[i], 16 * sizeof(bool));
		unsigned char* _key = Bool_A2UnsignedChar_A(key, 32);
		spn _Spn(_key);
		free(_key);
		_Spn.Encrypt(test);
		for (int j = 0; j < 16; j++)
		{
			if (Xor(test[j], y[i][j]))
			{
				return false;
			}
		}
	}
	return true;
}

