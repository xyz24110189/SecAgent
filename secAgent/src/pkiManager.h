#ifndef KOAL_PKIMANAGER_H
#define KOAL_PKIMANAGER_H

#include "comm/comm.h"
#include <stdint.h>
#include <string>

namespace koal {

class PkiManager
{
public:
	PkiManager();
	~PkiManager();

	static void Init();

	/*****************openssl1.1.1 原生使用模块*************/
	static bool Sm4Encrypt(const std::string &key, const std::string &srcData, std::string &encData);
	static bool Sm4Decrypt(const std::string &key, const std::string &encData, std::string &srcData);
	static bool PubEncrypt(const std::string &certPath, const std::string &srcData, std::string &encData);
	static bool PubDecrypt(const std::string &certPath, const std::string &encData, std::string &srcData);

	/*****************pkiAgent接口模块***************/
	static bool PkiInitAgent();
protected:
	static int32_t CalcCipherSize(int32_t size);

private:
	K_DISABLE_COPY(PkiManager);
};

}

#endif//KOAL_PKIMANAGER_H

