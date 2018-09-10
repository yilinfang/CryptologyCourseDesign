#include "rsa.h"



rsa::rsa()
{
	p = BN_new();
	q = BN_new();
	n = BN_new();
	n_eular = BN_new();
	e = BN_new();
	d = BN_new();
}


rsa::~rsa()
{
	BN_free(p);
	BN_free(q);
	BN_free(n);
	BN_free(n_eular);
	BN_free(e);
	BN_free(d);
}

void rsa::Generate()
{
	GeneratePrime(p, 512);
	GeneratePrime(q, 512);
	BN_CTX* ctx = BN_CTX_new();
	BN_mul(n, p, q, ctx);
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
	BN_CTX_free(ctx);
}

void rsa::GeneratePrime(BIGNUM* &bn, int size)
{
	BIGNUM* _bn = BN_new();
	while (1)
	{
		BN_rand(_bn, size, 0, 1);
		if (IsPrime(_bn, 512))
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


