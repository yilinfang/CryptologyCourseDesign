#include "rsa.h"



rsa::rsa()
{
	p = BN_new();
	q = BN_new();
	n = BN_new();
	n_eular = BN_new();
	e = BN_new();
	d = BN_new();
	R = BN_new();
	R_inv = BN_new();
	n_inv = BN_new();
	n_ = BN_new();
	q_ = BN_new();
	p_ = BN_new();
}


rsa::~rsa()
{
	BN_free(p);
	BN_free(q);
	BN_free(n);
	BN_free(n_eular);
	BN_free(e);
	BN_free(d);
	BN_free(R);
	BN_free(R_inv);
	BN_free(n_inv);
	BN_free(n_);
	BN_free(p_);
	BN_free(q_);
}

void rsa::Generate()
{
	GeneratePrime(p, 1024);
	GeneratePrime(q, 1024);
	BN_CTX* ctx = BN_CTX_new();
	BN_mul(n, p, q, ctx);
	BN_one(R);
	BN_lshift(R, R, 2048);
	//BN_mod_inverse(R_inv, R, n, ctx);
	GetInverse(R_inv, R, n);
	BN_mod_inverse(n_inv, n, R, ctx);
	BN_mod_sub(n_, R, n_inv, R, ctx);
	BIGNUM* _p, *_q;
	_p = BN_new();
	_q = BN_new();
	BN_sub(_p, p, BN_value_one());
	BN_sub(_q, q, BN_value_one());
	BN_mul(n_eular, _p, _q, ctx);
	BN_zero(e);
	BN_add_word(e, 65537);
	BN_mod_inverse(d, e, n_eular, ctx);
	BN_free(_p);
	BN_free(_q);
	BN_mod_inverse(q_, q, p, ctx);
	BN_mod_inverse(p_, p, q, ctx);
	BN_CTX_free(ctx);
}

void rsa::GeneratePrime(BIGNUM* &bn, int size)
{
	BIGNUM* _bn = BN_new();
	while (1)
	{
		BN_rand(_bn, size, 0, 1);
		if (IsPrime(_bn, size))
		{
			break;
		}
	}
	BN_copy(bn, _bn);
	BN_free(_bn);
}


bool rsa::IsPrime(BIGNUM * bn, int size)
{
	return MillerRabin(bn, 20);
}

bool rsa::MillerRabin(BIGNUM * bn, int rounds)
{
	BIGNUM *bn_t = BN_new();
	BN_zero(bn_t);
	BN_add_word(bn_t, 2);
	if (!BN_cmp(bn, bn_t))
	{
		BN_free(bn_t);
		return true;
	}
	if (!BN_cmp(bn, BN_value_one()) || !BN_is_odd(bn))
	{
		BN_free(bn_t);
		return false;
	}
	BN_free(bn_t);
	BIGNUM* u = BN_new();
	BN_copy(u, bn);
	BN_sub_word(u, 1);
	int t;
	for (t = 0; !BN_is_bit_set(u, 0); t++)
	{
		BN_rshift1(u, u);
	}
	BIGNUM* a = BN_new();
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* _n = BN_new();
	BN_copy(_n, bn);
	BN_sub_word(_n, 1);
	for (int i = 0; i < rounds; i++)
	{
		BN_rand_range(a,bn);
		ExpBySquare(x, a, u, bn);
		for (int j = 0; j < t; j++)
		{
			BN_mod_mul(y, x, x, bn, ctx);
			if (!BN_cmp(y, BN_value_one()) && BN_cmp(x, BN_value_one()) && BN_cmp(x, _n)) 
			{
				BN_free(a);
				BN_free(u);
				BN_free(x);
				BN_free(y);
				BN_free(_n);
				BN_CTX_free(ctx);
				return false;
			}
			BN_copy(x, y);
		}
		if (BN_cmp(y, BN_value_one()))
		{
			BN_free(a);
			BN_free(u);
			BN_free(x);
			BN_free(y);
			BN_free(_n);
			BN_CTX_free(ctx);
			return false;
		}
	}
	BN_free(a);
	BN_free(u);
	BN_free(x);
	BN_free(y);
	BN_free(_n);
	BN_CTX_free(ctx);
	return true;
}

void rsa::ExpBySquare(BIGNUM *& r, BIGNUM * a, BIGNUM * e, BIGNUM * m)
{
	BN_one(r);
	BIGNUM* b = BN_new();
	BN_copy(b, a);
	int n = BN_num_bits(e);
	BN_CTX * ctx = BN_CTX_new();
	for (int i = 0; i < n; i++)
	{
		if (BN_is_bit_set(e, i))
		{
			BN_mod_mul(r, r, b, m, ctx);
			BN_mod_mul(b, b, b, m, ctx);
		}
		else
		{
			BN_mod_mul(b, b, b, m, ctx);
		}
	}
	BN_free(b);
	BN_CTX_free(ctx);
}

void rsa::ChineseReminder(BIGNUM *& r, BIGNUM * p, BIGNUM * q, BIGNUM * a, BIGNUM * e, BIGNUM * m)
{
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* a1 = BN_new();
	BIGNUM* a2 = BN_new();
	ExpBySquare(a1, a, e, p);
	ExpBySquare(a2, a, e, q);
	BIGNUM* x1 = BN_new();
	BIGNUM* x2 = BN_new();
	BN_mod_mul(x1, a1, q, m, ctx);
	BN_mod_mul(x2, a2, p, m, ctx);
	BN_mod_mul(x1, x1, q_, m, ctx);
	BN_mod_mul(x2, x2, p_, m, ctx);
	BIGNUM* res = BN_new();
	BN_mod_add(res, x1, x2, m, ctx);
	BN_copy(r, res);
	BN_free(x1);
	BN_free(x2);
	BN_free(a1);
	BN_free(a2);
	BN_free(res);
}

void rsa::GetInverse(BIGNUM *& re, BIGNUM * n, BIGNUM * m)
{
	BIGNUM* _a = BN_new();
	BN_copy(_a, m);
	BIGNUM* _b = BN_new();
	BN_copy(_b, n);
	BIGNUM* _t = BN_new();
	BN_zero(_t);
	BIGNUM* t = BN_new();
	BN_one(t);
	BIGNUM* q = BN_new();
	BIGNUM* r = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_div(q, r, _a, _b, ctx);
	BIGNUM* temp = BN_new();
	while (!BN_is_zero(r))
	{
		BN_mul(q, q, t, ctx);
		BN_mod_sub(temp, _t, q, m, ctx);
		BN_copy(_t, t);
		BN_copy(t, temp);
		BN_copy(_a, _b);
		BN_copy(_b, r);
		BN_div(q, r, _a, _b, ctx);
	}
	if (int i = BN_is_one(_b))
	{
		BN_copy(re, t);
	}
	else
	{
		BN_free(re);
		re = NULL;
	}
	BN_free(_a);
	BN_free(_b);
	BN_free(_t);
	BN_free(t);
	BN_free(q);
	BN_free(r);
	BN_CTX_free(ctx);
	BN_free(temp);
}

void rsa::Montgomery(BIGNUM *& r, BIGNUM * A, BIGNUM * B)
{
	BN_CTX * ctx = BN_CTX_new();
	BIGNUM* t = BN_new();
	BN_mul(t, A, B, ctx);
	//BN_mod_mul(r, r, R_inv, n, ctx);
	BIGNUM* m = BN_new();
	//BN_mod_mul(m, t, n_, R, ctx); //模R即取m的后2048位，未找到取位API，以此替代
	BN_mul(m, t, n_, ctx);
	BN_mask_bits(m, 2048);
	BIGNUM* u = BN_new();
	BN_mul(u, m, n, ctx);
	BN_add(u, u, t);
	BN_rshift(u, u, 2048);
	if (BN_cmp(u, n) >= 0)
	{
		BN_sub(r, u, n);
	}
	else
	{
		BN_copy(r, u);
	}
	BN_free(t);
	BN_free(u);
	BN_free(m);
	BN_CTX_free(ctx);
}

void rsa::Montgomery(BIGNUM *& r)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_mod_mul(r, r, R, n, ctx);
	BN_CTX_free(ctx);
}

void rsa::Montgomery_Inverse(BIGNUM *& r)
{
	BN_CTX* ctx = BN_CTX_new();
	BN_mod_mul(r, r, R_inv, n, ctx);
	BN_CTX_free(ctx);
}

void rsa::ExpBySquare_mont(BIGNUM *& r, BIGNUM * a, BIGNUM * e)
{
	BN_one(r);
	Montgomery(r);
	BIGNUM* b = BN_new();
	BN_copy(b, a);
	Montgomery(b);
	int n = BN_num_bits(e);
	BN_CTX * ctx = BN_CTX_new();
	for (int i = 0; i < n; i++)
	{
		if (BN_is_bit_set(e, i))
		{
			Montgomery(r, r, b);
			Montgomery(b, b, b);
		}
		else
		{
			Montgomery(b, b, b);
		}
	}
	Montgomery_Inverse(r);
	BN_free(b);
	BN_CTX_free(ctx);
}

void rsa::Encrypt(unsigned char * input, unsigned char * output, int size)
{
	BIGNUM* in = BN_new();
	BN_zero(in);
	size /= 8;
	int flag = 127;
	for (int i = 0; i < size; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			if ((input[i] >> (7 - j)) & 0x1)
			{
				BN_set_bit(in, flag);
			}
			flag--;
		}
	}
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, e, n);
	for (int i = size - 1; i >= 0; i--)
	{
		unsigned char w = 0x80;
		for (int j = 7; j >=0 ; j--)
		{
			if (BN_is_bit_set(out, i * 8 + j))
			{
				output[size - 1 - i] += w;
			}
			w >>= 1;
		}
	}
	BN_free(in);
	BN_free(out);
}

char* rsa::Encrypt(char * input)
{
	BIGNUM* in = BN_new();
	BN_hex2bn(&in, input);
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, e, n);
	//ExpBySquare_mont(out, in, e);
	char* bufa = BN_bn2hex(out);
	return bufa;
}

void rsa::Encrypt(unsigned char * input, int len, char *& output)
{
	BIGNUM* in = BN_new();
	BN_zero(in);
	//int flag = 8 * len - 1;
	//for (int i = 0; i < len; i++)
	//{
	//	for (int j = 0; j < 8; j++)
	//	{
	//		if ((input[i] >> (7 - j)) & 0x1)
	//		{
	//			BN_set_bit(in, flag);
	//		}
	//		flag--;
	//	}
	//}
	BN_bin2bn(input, len, in);
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, e, n);
	output = BN_bn2hex(out);
	BN_free(in);
	BN_free(out);
}

void rsa::Decrypt(unsigned char * input, unsigned char * output, int size)
{
	BIGNUM* in = BN_new();
	BN_zero(in);
	size /= 8;
	int flag = 127;
	for (int i = 0; i < size; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			if ((input[i] >> (7 - j)) & 0x1)
			{
				BN_set_bit(in, flag);
			}
			flag--;
		}
	}
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, d, n);
	for (int i = size - 1; i >= 0; i--)
	{
		unsigned char w = 0x80;
		for (int j = 7; j >= 0; j--)
		{
			if (BN_is_bit_set(out, i * 8 + j))
			{
				output[size - 1 - i] += w;
			}
			w >>= 1;
		}
	}
	BN_free(in);
	BN_free(out);
}

char* rsa::Decrypt(char * input)
{
	BIGNUM* in = BN_new();
	BN_hex2bn(&in, input);
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, d, n);
	//ChineseReminder(out, p, q, in, d, n);
	//ExpBySquare_mont(out, in, d);
	char* bufa = BN_bn2hex(out);
	return bufa;
}

char * rsa::Decrypt_mont(char * input)
{
	BIGNUM* in = BN_new();
	BN_hex2bn(&in, input);
	BIGNUM* out = BN_new();
	//ExpBySquare(out, in, d, n);
	//ChineseReminder(out, p, q, in, d, n);
	ExpBySquare_mont(out, in, d);
	char* bufa = BN_bn2hex(out);
	return bufa;
}

char * rsa::Decrypt_reminder(char * input)
{
	BIGNUM* in = BN_new();
	BN_hex2bn(&in, input);
	BIGNUM* out = BN_new();
	//ExpBySquare(out, in, d, n);
	ChineseReminder(out, p, q, in, d, n);
	//ExpBySquare_mont(out, in, d);
	char* bufa = BN_bn2hex(out);
	return bufa;
}

void rsa::Decrypt(char * input, unsigned char *& output, int & len)
{
	BIGNUM* in = BN_new();
	BN_hex2bn(&in, input);
	BIGNUM* out = BN_new();
	ExpBySquare(out, in, d, n);
	//ExpBySquare_mont(out, in, e);
	BN_bn2bin(out, output);
	len = BN_num_bytes(out);
	BN_free(in);
	BN_free(out);
}
