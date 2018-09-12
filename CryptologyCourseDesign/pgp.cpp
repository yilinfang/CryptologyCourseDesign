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
	f1 = BIO_new_file(filepath_pub, "wb");
	f2 = BIO_new_file(filepath_pri, "wb");
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
	f1 = BIO_new_file(filepath_pub, "wb");
	f2 = BIO_new_file(filepath_pri, "wb");
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

void pgp::Encrypt(const char * filepath_pub, unsigned char * msg, int msg_len, unsigned char * r, unsigned * r_len)
{
	//EC_KEY * ec_key = EC_KEY_new();
	RSA* rsa = RSA_new();
	BIO *file = NULL;
	file = BIO_new_file(filepath_pub, "rb");
	//ec_key = PEM_read_bio_EC_PUBKEY(file, NULL, NULL, NULL);
	rsa = PEM_read_bio_RSAPublicKey(file, NULL, NULL, NULL);
	EVP_PKEY * key = EVP_PKEY_new();
	//EVP_PKEY_assign_EC_KEY(key, ec_key);
	EVP_PKEY_set1_RSA(key, rsa);
	RSA_free(rsa);
	BIO_free(file);
	EVP_PKEY_CTX * ctx = NULL;
	OpenSSL_add_all_ciphers();
	ctx = EVP_PKEY_CTX_new(key, NULL);
	EVP_PKEY_encrypt_init(ctx);
	printf("%d\n", *(r_len));
	getchar();
	EVP_PKEY_encrypt(ctx, r, r_len, msg, msg_len);
	printf("%d\n",*(r_len));
	getchar();
	EVP_PKEY_CTX_free(ctx);
}

void pgp::Encrypt(unsigned char* key,unsigned char * msg, int msg_len, unsigned char * r, int * r_len)
{
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	unsigned char iv[16] = { 0 };
	EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, iv);
	EVP_EncryptUpdate(ctx, r, r_len, msg, msg_len);
	EVP_EncryptFinal(ctx, r, r_len);
	EVP_CIPHER_CTX_free(ctx);
}

void pgp::Decrypt(const char * filepath_pri, unsigned char * msg, int msg_len, unsigned char * r, unsigned * r_len)
{
	//EC_KEY * ec_key = EC_KEY_new();
	RSA* rsa = RSA_new();
	BIO* file = NULL;
	file = BIO_new_file(filepath_pri, "rb");
	//ec_key = PEM_read_bio_ECPrivateKey(file, NULL, NULL, NULL);
	rsa = PEM_read_bio_RSAPrivateKey(file, NULL, NULL, NULL);
	EVP_PKEY * key = EVP_PKEY_new();
	//EVP_PKEY_assign_RSA(key, rsa);
	EVP_PKEY_set1_RSA(key, rsa);
	RSA_free(rsa);
	BIO_free(file);
	EVP_PKEY_CTX * ctx = NULL;
	OpenSSL_add_all_ciphers();
	ctx = EVP_PKEY_CTX_new(key, NULL);
	EVP_PKEY_decrypt_init(ctx);
	EVP_PKEY_decrypt(ctx, r, r_len, msg, msg_len);
	EVP_PKEY_CTX_free(ctx);
}

void pgp::Decrypt(unsigned char * key, unsigned char * msg, int msg_len, unsigned char * r, int * r_len)
{
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	unsigned char iv[16] = { 0 };
	EVP_DecryptInit(ctx, EVP_aes_256_ecb(),key, iv);
	EVP_DecryptUpdate(ctx, r, r_len, msg, msg_len);
	EVP_DecryptFinal(ctx, r, r_len);
	EVP_CIPHER_CTX_free(ctx);
}


