#include "pkiManager.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <plog/Log.h>
//#include <pkiAgent/pkiAgent4c.h>

#define PACKET_SIZE 16
#define PRIVATE_PASSWD "xyz2411089!@#$%^&*"

static unsigned char key[] = {
	0x21, 0x25, 0x37, 0x19, 0x46, 0x1b, 0xfd, 0xaf,
	0x45, 0xd2, 0x2a, 0x88, 0xe6, 0xf4, 0xb2, 0x19 };

static unsigned char iv[] = {
	0x41, 0x43, 0x35, 0x77, 0x49, 0x7b, 0x6d, 0xef,
	0xfd, 0xdf, 0xb1, 0x48, 0x96, 0x14, 0x92, 0x1f };

static void print_hex_dump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

//bool msgNotify(const kpkiResp * pResp, void * pUserData) {
//	if (pUserData) {
//		const char * pData = (const char *)pUserData;
//		LOG_ERROR << "get param from callBack msgNotify {param} = " << pData;
//	}
//
//	switch (pResp->msgType) {
//	case 0x0FFF0001: { ///设备插入
//		LOG_ERROR << "key insert";
//		break;
//	}
//	case 0x0FFF0002: { ///设备拔出
//		LOG_ERROR << "key remove";
//		break;
//	}
//	case 0x0FFF0003: { ///设备修改
//		LOG_ERROR << "key changed";
//		break;
//	}
//	case 0x0FFF0004: { ///Session关闭
//		LOG_ERROR << "session closed";
//		break;
//	}
//	}
//	return true;
//}


namespace koal {

PkiManager::PkiManager()
{

}

PkiManager::~PkiManager()
{

}

void PkiManager::Init()
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
}

bool PkiManager::Sm4Encrypt(const std::string &key, const std::string &srcData, std::string &encData)
{
	LOG_INFO << "PkiManager::Sm4Encrypt begin ...";
	int rc;
	int outl_tmp;
	int enc_len;
	bool bRet = false;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		LOG_ERROR << "Encrypt failed :ctx new";
		return false;
	}

	rc = EVP_CIPHER_CTX_set_padding(ctx, 1);
	if (rc != 1) {
		LOG_ERROR << "Encrypt failed : ctx set padding";
		goto out;
	}

	rc = EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, (unsigned char *)&key[0], iv);
	if (rc != 1) {
		LOG_ERROR << "Encrypt failed : EncryptInit";
		goto out;
	}

	encData.resize(CalcCipherSize(srcData.length()));
	rc = EVP_EncryptUpdate(ctx, (unsigned char *)&encData[0], &enc_len,
		(const unsigned char *)&srcData[0], srcData.length());
	if (rc != 1) {
		LOG_ERROR << "Encrypt failed : EncryptUpdate";
		goto out;
	}

	rc = EVP_EncryptFinal_ex(ctx, (unsigned char *)&encData[0] + enc_len, &outl_tmp);
	if (rc != 1) {
		LOG_ERROR << "Encrypt failed : EVP_EncryptFinal_ex";
		goto out;
	}

	enc_len += outl_tmp;
	//print_hex_dump((void *)&encData[0], enc_len);
	bRet = true;
	LOG_INFO << "PkiManager::Sm4Encrypt success!";

out:
	LOG_INFO << "PkiManager::Sm4Encrypt end ...";
	EVP_CIPHER_CTX_free(ctx);
	return bRet;
}

bool PkiManager::Sm4Decrypt(const std::string &key, const std::string &encData, std::string &srcData)
{
	LOG_INFO << "PkiManager::Sm4Decrypt begin ...";
	int rc;
	int outl;
	int outl_tmp;
	bool bRet = false;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		LOG_ERROR << "Decrypt failed :ctx new";
		return false;
	}

	rc = EVP_CIPHER_CTX_set_padding(ctx, 1);
	if (rc != 1) {
		LOG_ERROR << "Decrypt failed : ctx set padding";
		goto out;
	}

	rc = EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, (unsigned char *)&key[0], iv);
	if (rc != 1) {
		LOG_ERROR << "Decrypt failed : DecryptInit";
		goto out;
	}

	srcData.resize(encData.length());
	rc = EVP_DecryptUpdate(ctx, (unsigned char *)&srcData[0], &outl,
		(unsigned char *)&encData[0], encData.length());
	if (rc != 1) {
		LOG_ERROR << "Decrypt failed : DecryptUpdate";
		goto out;
	}

	rc = EVP_DecryptFinal_ex(ctx, (unsigned char *)&srcData[0] + outl, &outl_tmp);
	if (rc != 1) {
		LOG_ERROR << "Decrypt failed : DecryptFinal";
		goto out;
	}

	outl += outl_tmp;
	srcData.resize(outl);
	//print_hex_dump((void *)&srcData[0], outl);
	bRet = true;
	LOG_INFO << "PkiManager::Sm4Decrypt success!";

out:
	LOG_INFO << "PkiManager::Sm4Decrypt end ...";
	EVP_CIPHER_CTX_free(ctx);
	return bRet;
}

bool PkiManager::PubEncrypt(const std::string &certPath, const std::string &srcData, std::string &encData)
{
	bool bRet = false;
	X509 *cert = NULL;
	BIO *bio_cert = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;

	bio_cert = BIO_new_file(certPath.data(), "r");
	if (!bio_cert)
	{
		LOG_ERROR << "PkiManager::PubEncrypt BIO_new_file failed!";
		goto ERR;
	}

	/*FILE *file = fopen(certPath.data(), "r");
	if (!file)
	{
		LOG_ERROR << "PkiManager::PubEncrypt open cert file = " << certPath << "failed!";
		goto ERR;
	}
		
	rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
	if (!rsa)
	{
		LOG_ERROR << "PkiManager::PubEncrypt PEM_read_RSAPublicKey failed!";
		goto ERR;
	}

	fclose(file);
	file = NULL;*/

	cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL);
	if (!cert)
	{
		(void)BIO_reset(bio_cert);
		BIO_free(bio_cert);

		bio_cert = BIO_new_file(certPath.data(), "rb");
		if (!bio_cert)
		{
			LOG_ERROR << "PkiManager::PubEncrypt BIO_new_file failed!";
			goto ERR;
		}

		cert = d2i_X509_bio(bio_cert, NULL);
	}

	if (!cert)
	{
		LOG_ERROR << "PkiManager::PubEncrypt build x509 object from bio failed!";
		goto ERR;
	}

	pkey = X509_get_pubkey(cert);
	if (!pkey) {
		LOG_ERROR << "PkiManager::PubEncrypt X509_get_pubkey failed!";
		goto ERR;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
	{
		LOG_ERROR << "PkiManager::PubEncrypt EVP_PKEY_get1_RSA failed!";
		goto ERR;
	}

	encData.resize(RSA_size(rsa));
	int nRet = RSA_public_encrypt(srcData.length(), 
		(unsigned char *)&srcData[0], 
		(unsigned char *)&encData[0], 
		rsa,
		RSA_PKCS1_PADDING);
	if (nRet <= 0)
	{
		LOG_ERROR << "PkiManager::PubEncrypt RSA_public_encrypt failed!";
		goto ERR;
	}

	bRet = true;

ERR:
	if (rsa)
		RSA_free(rsa);

	if (pkey)
		EVP_PKEY_free(pkey);

	if (cert)
		X509_free(cert);

	if (bio_cert)
		BIO_free(bio_cert);

	return bRet;
}

bool PkiManager::PubDecrypt(const std::string &certPath, const std::string &encData, std::string &srcData)
{
	bool bRet = false;
	EVP_PKEY *pkey = NULL;
	BIO *bio_prikey = NULL;
	RSA *rsa = NULL;

	bio_prikey = BIO_new_file(certPath.data(), "r");
	if (!bio_prikey)
	{
		LOG_ERROR << "PkiManager::PubDecrypt BIO_new_file failed!";
		goto ERR;
	}

	/*FILE *file = fopen(certPath.data(), "r");
	if (!file)
	{
		LOG_ERROR << "PkiManager::PubDecrypt open cert file = " << certPath << "failed!";
		goto ERR;
	}*/

	pkey = PEM_read_bio_PrivateKey(bio_prikey, NULL, NULL, PRIVATE_PASSWD);
	if (!pkey)
	{
		LOG_ERROR << "PkiManager::PubDecrypt PEM_read_PrivateKey failed!";
		goto ERR;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
	{
		LOG_ERROR << "PkiManager::PubDecrypt EVP_PKEY_get1_RSA failed!";
		goto ERR;
	}

	srcData.resize(RSA_size(rsa));
	int nRet = RSA_private_decrypt(encData.length(),
		(unsigned char *)&encData[0],
		(unsigned char *)&srcData[0],
		rsa,
		RSA_PKCS1_PADDING);
	if (nRet <= 0)
	{
		LOG_ERROR << "PkiManager::PubDecrypt RSA_private_decrypt failed!";
		goto ERR;
	}

	bRet = true;

ERR:
	//if (file) 
		//fclose(file);
	
	if (pkey)
		EVP_PKEY_free(pkey);

	if (rsa)
		RSA_free(rsa);

	if (bio_prikey)
		BIO_free(bio_prikey);

	return bRet;
}

int32_t PkiManager::CalcCipherSize(int32_t size)
{
	int8_t mod = size % PACKET_SIZE;
	if (mod)
		size += (PACKET_SIZE - mod);
	else
		size += PACKET_SIZE;
	return size;
}

bool PkiManager::PkiInitAgent()
{
	/*do {
		if (!createAgent(&msgNotify, NULL, NULL)) {
			LOG_ERROR << "PkiManager::PkiInitAgent create Agent failed";
			break;
		}
		///登录
		if (!loginAgent("IMSecAgent", "A38F20C4BC1A41AAACFEB026F615045F", "A38F20C4BC1A41AAA")) {
			LOG_ERROR << "login failed";
			break;
		}

		///登出
		logoutAgent();
		///释放agent
		releaseAgent();
	} while (0);*/
}

}