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

void pgp::Digest(const unsigned char * msg, int len, unsigned char * dig, unsigned int * dig_len)
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
	EVP_PKEY_encrypt(ctx, r, r_len, msg, msg_len);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
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

void pgp::Encrypt(char * password, const char* filepath_pub, const char* filepath_pri,const char* filepath_in,const char* filepath_out)
{
	FILE* f1 = NULL;
	fopen_s(&f1, filepath_in, "rb");
	FILE* f2 = NULL;
	fopen_s(&f2, filepath_out, "wb");
	unsigned char* msg = (unsigned char*)malloc(0x1146400 * sizeof(unsigned char));
	char* output = (char*)malloc(0x1150000 * sizeof(char));
	unsigned char* bufa = (unsigned char*)malloc(0x1150000 * sizeof(unsigned char));
	unsigned char* p = bufa;
	char c = fgetc(f1);
	int i = 0;
	while (c != EOF)
	{
		msg[i] = c;
		i++;
		c = fgetc(f1);
	}
	int msg_len = i;
	unsigned char* bufa1;
	bufa1 = (unsigned char*)malloc(0x1150000 * sizeof(unsigned char));
	unsigned char* dig = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	unsigned char* sig = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	unsigned len1,len2;
	Digest(msg, msg_len, dig, &len1);
	Signature(filepath_pri,dig, len1, sig, &len2);
	len1 = 0;
	memcpy(p, &len2, sizeof(unsigned int));
	p += 4;
	len1 += 4;
	memcpy(p, sig, len2 * sizeof(unsigned char));
	p += len2;
	len1 += len2;
	memcpy(p, &msg_len, sizeof(unsigned));
	p += 4;
	len1 += 4;
	memcpy(p, msg, msg_len * sizeof(char));
	len1 += msg_len;
	unsigned char key_s[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	OpenSSL_add_all_ciphers();
	memcpy(bufa1, password, strlen(password) * sizeof(char));
	EVP_BytesToKey(EVP_aes_256_cfb(), EVP_md5(), NULL, bufa1, strlen(password), 10, key_s, iv);
	EVP_EncryptInit(ctx, EVP_aes_256_cfb(),key_s, iv);
	int len3,_len;
	len3 = 0;
	unsigned char *p1, *p2;
	p1 = bufa;
	p2 = bufa1;
	for (;;)
	{
		if ((int)(len1 - EVP_MAX_BLOCK_LENGTH) > 0)
		{
			EVP_EncryptUpdate(ctx, p2, &_len, p1, EVP_MAX_BLOCK_LENGTH);
			p1 += EVP_MAX_BLOCK_LENGTH;
			p2 += _len;
			len3 += _len;
			len1 -= EVP_MAX_BLOCK_LENGTH;
		}
		else
		{
			EVP_EncryptUpdate(ctx, p2, &_len, p1, len1);
			len3 += _len;
			break;
		}
	}
	EVP_EncryptFinal(ctx, p2, &_len);
	len3 += _len;
	memcpy(bufa, key_s, EVP_MAX_KEY_LENGTH * sizeof(unsigned char));
	memcpy(bufa + EVP_MAX_KEY_LENGTH, iv, EVP_MAX_IV_LENGTH * sizeof(unsigned char));
	unsigned len4;
	unsigned char* bufa2 = (unsigned char*)malloc(0x1024 * sizeof(unsigned char));
	Encrypt(filepath_pub, bufa, EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH, bufa2, &len4);
	memcpy(output, &len4, sizeof(unsigned));
	memcpy(output + 4, bufa2, len4 * sizeof(unsigned char));
	memcpy(output + 4 + len4, &len3, sizeof(int));
	memcpy(output + 4 + len4 + 4, bufa1, len3 * sizeof(unsigned char));
	for (i = 0; i < 4 + len4 + 4 + len3; i++)
	{
		fprintf_s(f2,"%c", output[i]);
	}
	free(msg);
	free(output);
	free(sig);
	free(dig);
	free(bufa);
	free(bufa1);
	free(bufa2);
	EVP_CIPHER_CTX_free(ctx);
	fclose(f1);
	fclose(f2);
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
	EVP_PKEY_free(key);
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

int pgp::Decrypt(const char * filepath_pub, const char * filepath_pri, const char * filepath_in, const char * filepath_out)
{
	FILE *f1, *f2;
	fopen_s(&f1, filepath_in, "rb");
	fopen_s(&f2, filepath_out, "wb");
	unsigned len1;
	char size[4];
	size[0] = fgetc(f1);
	size[1] = fgetc(f1);
	size[2] = fgetc(f1);
	size[3] = fgetc(f1);
	memcpy(&len1, size, sizeof(unsigned));
	unsigned char* bufa1 = (unsigned char*)malloc(0x1150000 * sizeof(unsigned char));
	for (int i = 0; i < len1; i++)
	{
		bufa1[i] = fgetc(f1);
	}
	unsigned char key_s[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char* bufa2 = (unsigned char*)malloc(0x1150000 * sizeof(unsigned char));
	unsigned len2;
	Decrypt(filepath_pri, bufa1, len1, bufa2 ,&len2);
	memcpy(key_s, bufa2, EVP_MAX_KEY_LENGTH * sizeof(unsigned char));
	memcpy(iv, bufa2 + EVP_MAX_KEY_LENGTH, EVP_MAX_IV_LENGTH * sizeof(unsigned char));
	size[0] = fgetc(f1);
	size[1] = fgetc(f1);
	size[2] = fgetc(f1);
	size[3] = fgetc(f1);
	memcpy(&len1, size, sizeof(unsigned));
	for (int i = 0; i < len1; i++)
	{
		bufa1[i] = fgetc(f1);
	}
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	OpenSSL_add_all_ciphers();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key_s, iv);
	int len3, _len;
	len3 = 0;
	unsigned char *p1, *p2;
	p1 = bufa1;
	p2 = bufa2;
	for (;;)
	{
		if ((int)(len1 - EVP_MAX_BLOCK_LENGTH) > 0)
		{
			EVP_DecryptUpdate(ctx, p2, &_len, p1, EVP_MAX_BLOCK_LENGTH);
			//EVP_EncryptUpdate(ctx, p2, &_len, p1, EVP_MAX_BLOCK_LENGTH);
			p1 += EVP_MAX_BLOCK_LENGTH;
			p2 += _len;
			len3 += _len;
			len1 -= EVP_MAX_BLOCK_LENGTH;
		}
		else
		{
			//EVP_EncryptUpdate(ctx, p2, &_len, p1, len1);
			EVP_DecryptUpdate(ctx, p2, &_len, p1, len1);
			len3 += _len;
			break;
		}
	}
	//EVP_DecryptUpdate(ctx, bufa2, &_len, bufa1, len1);
	//len3 += _len;
	EVP_DecryptFinal_ex(ctx, p2, &_len);
	len3 += _len;
	EVP_CIPHER_CTX_free(ctx);
	unsigned char* p = bufa2;
	unsigned sig_len;
	unsigned char* sig = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	unsigned msg_len;
	unsigned char* msg = (unsigned char*)malloc(0x1150000 * sizeof(unsigned char));
	memcpy(&sig_len, p, sizeof(unsigned));
	p += 4;
	memcpy(sig, p, sig_len * sizeof(unsigned char));
	p += sig_len;
	memcpy(&msg_len, p, sizeof(unsigned));
	p += 4;
	memcpy(msg, p, msg_len * sizeof(unsigned char));
	for (int i = 0; i < msg_len; i++)
	{
		fprintf(f2,"%c", msg[i]);
		printf("%c", msg[i]);
	}
	printf("\n");
	unsigned dig_len;
	unsigned char* dig = (unsigned char*)malloc(1024 * sizeof(unsigned char));
	Digest(msg, msg_len, dig, &dig_len);
	int res = Verify(filepath_pub, dig, dig_len, sig, sig_len);
	free(dig);
	free(sig);
	free(msg);
	free(bufa1);
	free(bufa2);
	return res;
}


