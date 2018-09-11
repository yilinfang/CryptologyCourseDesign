#include "pgp.h"

void pgp::CreateECKeys(const char * filepath_pub, const char * filepath_pri)
{
	EC_KEY * key = EC_KEY_new();
	EC_builtin_curve * curves;
	EC_GROUP* group;
	int crv_len;
	unsigned int nid;
	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve) * crv_len);
	EC_get_builtin_curves(curves, crv_len);
	srand((unsigned)time(NULL));
	nid = curves[rand()%crv_len].nid;
	group = EC_GROUP_new_by_curve_name(nid);
	EC_KEY_set_group(key, group);
	EC_KEY_generate_key(key);
	BIO* f1, *f2;
	f1 = BIO_new_file(filepath_pub, "w");
	f2 = BIO_new_file(filepath_pri, "w");
	PEM_write_bio_EC_PUBKEY(f1, key);
	PEM_write_bio_ECPrivateKey(f2, key, NULL, NULL, 0, NULL, NULL);
	BIO_flush(f1);
	BIO_flush(f2);
	BIO_free(f1);
	BIO_free(f2);
	EC_KEY_free(key);
	free(curves);
}

void pgp::CreateRSAKeys(const char * filepath_pub, const char * filepath_pri)
{
	RSA *r = RSA_new();
	BIGNUM * e = BN_new();
	BN_set_word(e, 65537);
	RSA_generate_key_ex(r, 1024, e, NULL);
	BN_free(e);
	BIO* f1, *f2;
	f1 = BIO_new_file(filepath_pub, "w");
	f2 = BIO_new_file(filepath_pri, "w");
	PEM_write_bio_RSAPublicKey(f1, r);
	PEM_write_bio_RSAPrivateKey(f2, r, NULL, NULL, 0, NULL, NULL);
	BIO_flush(f1);
	BIO_flush(f2);
	BIO_free(f1);
	BIO_free(f2);
	RSA_free(r);
}

void pgp::Signature(const char * filepath_pri, const unsigned char * dig, unsigned int dlen, unsigned char * sig, unsigned int * sig_len)
{
	EC_KEY * key = NULL;
	BIO *file = NULL;
	file = BIO_new_file(filepath_pri, "rb");
	key = PEM_read_bio_ECPrivateKey(file, NULL, NULL, NULL);
	ECDSA_sign(0, dig, dlen, sig, sig_len, key);
	BIO_free(file);
	EC_KEY_free(key);
}

void pgp::Digest(const char * msg, int len, unsigned char * dig, unsigned int * dig_len)
{
	EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(md_ctx);
	EVP_DigestInit(md_ctx, EVP_sha1());
	EVP_DigestUpdate(md_ctx, msg, len);
	EVP_DigestFinal(md_ctx, dig, dig_len);
	EVP_MD_CTX_free(md_ctx);
}

int pgp::Verify(const char * filepath_pub, const unsigned char * dig, unsigned int dlen, unsigned char * sig, unsigned int slen)
{
	EC_KEY * key = NULL;
	BIO *file = NULL;
	file = BIO_new_file(filepath_pub, "rb");
	key = PEM_read_bio_EC_PUBKEY(file, NULL, NULL, NULL);
	int n = ECDSA_verify(0, dig, dlen, sig, slen, key);
	BIO_free(file);
	EC_KEY_free(key);
	return n;
}

void pgp::Encrypt(char * filepath_pub, unsigned char * msg, int msg_len, unsigned char * r, int * r_len)
{
	EC_KEY * key = NULL;
	BIO * file = NULL;
	file = BIO_new_file(filepath_pub, "rb");
	key = PEM_read_bio_EC_PUBKEY(file, NULL, NULL, NULL);

}


