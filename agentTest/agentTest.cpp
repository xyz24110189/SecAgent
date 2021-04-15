// agentTest.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <secAgent.h>

int main()
{
	koal::SecAgent agent;
	agent.InitConfig("secAgent", 3600);

	agent.StoreUserCert("xyz2411089", "F:\\work\\project\\bmw\\projects\\secAgent\\bin\\x64\\Release\\cert.cer");

	std::string pubEncData;
	agent.PbEncrypt("xyz2411089", "123456789", pubEncData);
	printf("pubEncData = %s\n", pubEncData.data());

	std::string pubSrcData;
	agent.PbDecrypt("xyz2411089", pubEncData, pubSrcData);
	printf("pubSrcData = %s\n", pubSrcData.data());

	std::string encData;
	std::string srcData = "���Ǻõľ�����õ�ѽ��ѽ�ǰ�˹�ٷҰ�";//"1234567891234567";
	std::string key = agent.GeneralKey();
	agent.StoreKeyByUserId("xyz2411089", key);
	int8_t nRet = agent.SymEncrypt(/*"xyz2411089", key, */srcData, encData);
	if (0 == nRet)
		printf("encData = %s\n", encData.data());

	std::string srcData1;
	bool bRet = agent.SymDecrypt(/*"xyz2411089", key, */"kGTbeLW1XqtDlWjK3YxA+g==", srcData1);
	if (bRet)
		printf("srcData1 = %s\n", srcData1.data());

	getchar();

	std::string outEnFilePath1;
	std::string outEnFilePath2;
	agent.SecEncryptFile(key, "E:\\Ѹ������\\sogou_pinyin_97b.exe", [&outEnFilePath1](bool res, const std::string &enFilePath) {
		if (res)
		{
			outEnFilePath1 = enFilePath;
			printf("Encrypt file = %s\n", enFilePath.data());
		}
	});

	agent.SecEncryptFile(key, "E:\\Ѹ������\\Win32OpenSSL-1_1_1h.exe", [&outEnFilePath2](bool res, const std::string &enFilePath) {
		if (res)
		{
			outEnFilePath2 = enFilePath;
			printf("Encrypt file = %s\n", enFilePath.data());
		}
	});

	getchar();

	std::string outSrcFilePath1;
	std::string outSrcFilePath2;
	agent.SecDecryptFile(key, outEnFilePath1, [&outSrcFilePath1](bool res, const std::string &srcFilePath) {
		if (res)
		{
			outSrcFilePath1 = srcFilePath;
			printf("Decrypt file = %s\n", srcFilePath.data());
		}
	});

	agent.SecDecryptFile(key, outEnFilePath2, [&outSrcFilePath2](bool res, const std::string &srcFilePath) {
		if (res)
		{
			outSrcFilePath2 = srcFilePath;
			printf("Decrypt file = %s\n", srcFilePath.data());
		}
	});

	getchar();
    return 0;
}

