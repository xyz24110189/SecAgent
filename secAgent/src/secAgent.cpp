#include "secAgent.h"
#include "comm/utils.h"
#include "comm/comm.h"
#include "comm/threadPool.h"
#include "comm/platformFolders.h"
#include "base64/base64.h"
#include "sqlCipherDb.h"
#include "pkiManager.h"
#include <plog/Log.h>

namespace koal {

static std::string gAppDir;

static bool SecEncryptFile(const std::string &symKey,
	const std::string &srcFilePath,
	std::string &encFilePath)
{
	LOG_INFO << "EncryptFile begin ...";

	FILE* infp = NULL;
	FILE* outfp = NULL;
	char *buffer = NULL;
	bool bRet = false;
	std::string enData;
	std::string baseName;

	if (!utils::PathExist(srcFilePath.data()))
	{
		LOG_ERROR << "not exist the file! name = " << srcFilePath;
		goto ERR;
	}

	infp = fopen(srcFilePath.data(), "rb");
	if (!infp) {
		LOG_ERROR << "failed to open the file infp = " << srcFilePath;
		goto ERR;
	}

	baseName = srcFilePath.substr(srcFilePath.find_last_of("/\\") + 1);
	encFilePath = gAppDir + SLASH + "enc_files";
	utils::CreateDir(encFilePath.data());

	encFilePath += SLASH;
	encFilePath += baseName;

	outfp = fopen(encFilePath.data(), "wb");
	if (!outfp) {
		LOG_ERROR << "failed to open the file outfp = " << encFilePath;
		goto ERR;
	}

	buffer = new char[ENCRYPT_PER_SIZE];
	while (!feof(infp))
	{
		size_t nRet = fread(buffer, sizeof(char), ENCRYPT_PER_SIZE, infp);
		if (nRet > 0)
		{
			std::string data(buffer, nRet);

			bool bRet = PkiManager::Sm4Encrypt(symKey, data, enData);
			if (bRet)
				fwrite(&enData[0], sizeof(char), enData.length(), outfp);
			else
				goto ERR;
		}
	}

	bRet = true;
ERR:
	if (infp)
		fclose(infp);
	if (outfp)
		fclose(outfp);
	if (buffer)
		delete[]buffer;
	LOG_INFO << "EncryptFile end ...";

	return bRet;
}

static bool SecDecryptFile(const std::string &symKey,
	const std::string &encFilePath,
	std::string &srcFilePath)
{
	LOG_INFO << "DecryptFile begin ...";

	FILE* infp = NULL;
	FILE* outfp = NULL;
	char *buffer = NULL;
	bool bRet = false;
	std::string data;
	std::string baseName;

	if (!utils::PathExist(encFilePath.data()))
	{
		LOG_ERROR << "not exist the file! name = " << encFilePath;
		goto ERR;
	}

	infp = fopen(encFilePath.data(), "rb");
	if (!infp) {
		LOG_ERROR << "failed to open the file infp = " << encFilePath;
		goto ERR;
	}


	baseName = encFilePath.substr(encFilePath.find_last_of("/\\") + 1);
	srcFilePath = gAppDir + SLASH + "plain_files";
	utils::CreateDir(srcFilePath.data());

	srcFilePath += SLASH;
	srcFilePath += baseName;

	outfp = fopen(srcFilePath.data(), "wb");
	if (!outfp) {
		LOG_ERROR << "failed to open the file outfp = " << srcFilePath;
		goto ERR;
	}

	buffer = new char[DECRYPT_PER_SIZE];
	while (!feof(infp))
	{
		size_t nRet = fread(buffer, sizeof(char), DECRYPT_PER_SIZE, infp);
		if (nRet > 0)
		{
			std::string enData(buffer, nRet);

			bool bRet = PkiManager::Sm4Decrypt(symKey, enData, data);
			if (bRet)
				fwrite(&data[0], sizeof(char), data.length(), outfp);
			else
				goto ERR;
		}
	}

	bRet = true;

ERR:
	if (infp)
		fclose(infp);
	if (outfp)
		fclose(outfp);
	if (buffer)
		delete[]buffer;
	LOG_INFO << "DecryptFile end ...";

	return bRet;
}
class Private 
{
public:
	Private() : _threshold(0) {}

	void InitLog();
	void InitDB();
	void InitPki();

private:
	friend SecAgent;
	std::string _appDir;
	int64_t _threshold;
	ThreadPool _threadPoop;
};

void Private::InitLog()
{
	/* 日志初始化 */
	std::string logPath = _appDir + SLASH + LOG_PATH_NAME;
	utils::CreateDir(logPath.data());
	logPath += SLASH;
	logPath += "secAgent.log";
	plog::init(plog::debug, logPath.c_str(), 10000000, 10);
}

void Private::InitDB()
{
	SqlCipherDb::GetInstance()->InitDb(_appDir);
}

void Private::InitPki()
{
	PkiManager::Init();
}

SecAgent::SecAgent() 
{
	_d = new Private();
}

SecAgent::~SecAgent() 
{
	FREE_OBJECT(_d);
}

void SecAgent::InitConfig(const std::string &appDir/*in*/, 
	int64_t threshold/*in*/)
{
	_d->_appDir = sago::getDataHome() + SLASH + appDir;
	_d->_threshold = threshold;
	_d->InitLog();
	_d->InitDB();
	_d->InitPki();
	_d->_threadPoop.setWorkerThreadCount();

	gAppDir = _d->_appDir;
	utils::CreateDir(_d->_appDir.data());
}

bool SecAgent::IsKeyValid(const std::string &accid/*in*/)
{
	/* code 根据用户id查询用户最后一次加解密操作时间 */
	int64_t lastTime = 0;
	bool bRet = SqlCipherDb::GetInstance()->QueryLastEncTime(accid.data(), lastTime);

	if (bRet)
	{
		int64_t curMs = utils::GetCurentMs();
		return (curMs - lastTime) / 1000 < _d->_threshold;
	}

	return bRet;
}

bool SecAgent::StoreUserCert(const std::string &accid/*in*/,
	const std::string &certPath/*in*/)
{
	bool bRet = utils::PathExist(certPath.data());
	if (bRet)
	{
		std::string baseName = certPath.substr(certPath.find_last_of("/\\") + 1);
		std::string destPath = _d->_appDir + SLASH + "certs";
		utils::CreateDir(destPath.data());

		destPath += SLASH;
		destPath += baseName;
		if (utils::KCopyFile(certPath.data(), destPath.data()))
			bRet = SqlCipherDb::GetInstance()->InsertUserCert(accid.data(), destPath.data());
	}
	
	return bRet;
}

bool SecAgent::CertExist(const std::string &accid/*in*/)
{
	std::string certPath;
	bool bRet = SqlCipherDb::GetInstance()->QueryCertByAccid(accid.data(), certPath);
	if (bRet)
		bRet = utils::PathExist(certPath.data());

	return bRet;
}

std::string SecAgent::GeneralKey()
{
	return utils::RandomString(16);
}

std::string SecAgent::GetKeyByUserId(const std::string &accid/*in*/)
{
	std::string symKey;
	bool bRet = SqlCipherDb::GetInstance()->QueryKeyByAccid(accid.data(), symKey);
	if (!bRet)
		LOG_ERROR << "GetKeyByUserId failed where accid = " << accid;

	return symKey;
}

bool SecAgent::StoreKeyByUserId(const std::string &accid/*in*/,
	const std::string &key/*in*/)
{
	std::string symKey = GetKeyByUserId(accid);
	if (symKey.empty())
		SqlCipherDb::GetInstance()->InsertKey(accid.data(), key.data());
	else
		SqlCipherDb::GetInstance()->UpdateKey(accid.data(), key.data());
}

int8_t SecAgent::SymEncrypt(const std::string &accid, 
	const std::string &key/*in*/,
	const std::string &data/*in*/,
	std::string &enData/*out*/)
{
	bool bRet = IsKeyValid(accid);
	int32_t nRet = bRet ? 0 : 2;
	if (bRet)
	{
		bRet = PkiManager::Sm4Encrypt(key, data, enData);
		nRet = bRet ? 0 : 1;
		if (bRet)
			enData = base64_encode(enData);

		SqlCipherDb::GetInstance()->UpdateLastEncTime(accid.data(), utils::GetCurentMs());
	}
	
	return nRet;
}

bool SecAgent::SymDecrypt(const std::string &accid, 
	const std::string &key/*in*/,
	const std::string &enData/*in*/,
	std::string &data/*out*/)
{
	const std::string &originData = base64_decode(enData);
	SqlCipherDb::GetInstance()->UpdateLastEncTime(accid.data(), utils::GetCurentMs());

	bool bRet = PkiManager::Sm4Decrypt(key, originData, data);
	return bRet;
}

bool SecAgent::PbEncrypt(const std::string &accid/*in*/,
	const std::string &data/*in*/,
	std::string &enData/*out*/)
{
	std::string certPath;
	bool bRet = SqlCipherDb::GetInstance()->QueryCertByAccid(accid.data(), certPath);
	if (bRet)
		bRet = PkiManager::PubEncrypt(certPath, data, enData);

	if (bRet)
		enData = base64_encode(enData);

	return bRet;
}

bool SecAgent::PbDecrypt(const std::string &accid/*in*/,
	const std::string &enData/*in*/,
	std::string &data/*out*/)
{
	std::string certPath = utils::GetApplicationPath() + "private.dll";
	const std::string &originData = base64_decode(enData);
	bool bRet = PkiManager::PubDecrypt(certPath, originData, data);

	return bRet;
}

bool SecAgent::IsPbDecrypt(const std::string &accid/*in*/,
	const std::string &enData/*in*/)
{
	return SqlCipherDb::GetInstance()->QueryExistByEncKey(accid.data(), enData.data());
}

void SecAgent::SecEncryptFile(const std::string &symKey,
	const std::string &srcFilePath,
	ReturnFunc callback)
{
	FileDecryptInfo info;
	info.symKey = symKey;
	info.inFilePath = srcFilePath;
	info.decCallback = std::bind(koal::SecEncryptFile,
								 std::placeholders::_1,
								 std::placeholders::_2, 
								 std::placeholders::_3);
	info.RetCallback = std::move(callback);
	
	FileDecryption *decryption = new FileDecryption(std::move(info));
	_d->_threadPoop.pushWorkToThread(decryption);
}

void SecAgent::SecDecryptFile(const std::string &symKey,
	const std::string &encFilePath,
	ReturnFunc callback)
{
	FileDecryptInfo info;
	info.symKey = symKey;
	info.inFilePath = encFilePath;
	info.decCallback = std::bind(koal::SecDecryptFile,
		std::placeholders::_1,
		std::placeholders::_2,
		std::placeholders::_3);
	info.RetCallback = std::move(callback);

	FileDecryption *decryption = new FileDecryption(std::move(info));
	_d->_threadPoop.pushWorkToThread(decryption);
}

int8_t SecAgent::SymEncrypt(const std::string &data/*in*/,
	std::string &enData/*out*/)
{
	bool bRet = PkiManager::Sm4Encrypt(SYM_ENCRYPT_KEY, data, enData);
	if (bRet)
		enData = base64_encode(enData);

	return bRet ? 0 : 1;
}

bool SecAgent::SymDecrypt(const std::string &enData/*in*/,
	std::string &data/*out*/)
{
	if (!utils::IsBase64(enData))
	{
		data = enData;
		return false;
	}
	const std::string &originData = base64_decode(enData);
	return PkiManager::Sm4Decrypt(SYM_ENCRYPT_KEY, originData, data);
}

}

