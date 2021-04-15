#ifndef KOAL_SECAGENT_H
#define KOAL_SECAGENT_H

#include "comm/global.h"
#include <stdint.h>
#include <string>
#include <functional>

namespace koal {

class Private;

class KOAL_SEC_API SecAgent
{
	typedef std::function<void (bool res, const std::string &)> ReturnFunc;

public:
	explicit SecAgent();
	~SecAgent();

	/**
	@ brief: 初始化接口，用于设置appdata目录、阈值
	@ param[in] appDir    数据保存目录
	@ param[in] threshold 阈值(单位:妙)
	@ return void
	*/
	void InitConfig(const std::string &appDir/*in*/,
		int64_t threshold/*in*/);

	/**
	@ brief: 判断对称秘钥是否失效
	@ param[in] accid 用户id
	@ return bool true:可用/false:失效
	*/
	bool IsKeyValid(const std::string &accid/*in*/);

	/**
	@ brief: 保存用户证书接口
	@ param[in] accid    用户id
	@ param[in] certPath 证书路径
	@ return bool true:成功/false:失败
	*/
	bool StoreUserCert(const std::string &accid/*in*/,
		const std::string &certPath/*in*/);

	/**
	@ brief: 本地查询用户证书是否存在
	@ param[in] accid 用户id
	@ return bool true:成功/false:失败
	*/
	bool CertExist(const std::string &accid/*in*/);

	/**
	@ brief: 生成16位对称秘钥
	@ return std::string 对称秘钥
	*/
	std::string GeneralKey();

	/**
	@ brief: 根据用户id获取对称秘钥
	@ param[in] accid 用户id
	@ return std::string 对称秘钥
	*/
	std::string GetKeyByUserId(const std::string &accid/*in*/);

	/**
	@ brief: 根据用户id存储对称秘钥
	@ param[in] accid 用户id
	@ param[in] key   对称秘钥
	@ return bool true:成功/false:失败
	*/
	bool StoreKeyByUserId(const std::string &accid/*in*/,
		const std::string &key/*in*/);

	/**
	@ brief: 对称加密接口
	@ param[in]  accid  用户ID
	@ param[in]  key    对称加密秘钥
	@ param[in]  data   原始数据
	@ param[out] enData 加密数据
	@ return int8_t 0：加密成功; 1：加密失败; 2：对称秘钥阈值过期
	*/
	int8_t SymEncrypt(const std::string &accid/*in*/, 
		const std::string &key/*in*/,
		const std::string &data/*in*/,
		std::string &enData/*out*/);

	/**
	@ brief: 对称解密接口
	@ param[in]  accid  用户ID
	@ param[in]  key    对称加密秘钥
	@ param[in]  enData 加密数据
	@ param[out] data   原始数据
	@ return bool true：解密成功/false：解密失败
	*/
	bool SymDecrypt(const std::string &accid/*in*/, 
		const std::string &key/*in*/,
		const std::string &enData/*in*/,
		std::string &data/*out*/);

	/**
	@ brief: 公钥加密接口
	@ param[in]  accid  用户id
	@ param[in]  data   原始数据
	@ param[out] enData 加密数据
	@ return bool true:成功/false:失败
	*/
	bool PbEncrypt(const std::string &accid/*in*/,
		const std::string &data/*in*/,
		std::string &enData/*out*/);

	/**
	@ brief: 公钥解密接口
	@ param[in]  accid  用户id
	@ param[in]  enData 加密数据
	@ param[out] data   原始数据
	@ return bool true:成功/false:失败
	*/
	bool PbDecrypt(const std::string &accid/*in*/,
		const std::string &enData/*in*/,
		std::string &data/*out*/);

	/**
	@ brief: 判断数据是否已被公钥解密
	@ param[in] accid
	@ param[in] enData
	@ return bool true:已解密/false:未解密
	*/
	bool IsPbDecrypt(const std::string &accid/*in*/,
		const std::string &enData/*in*/);

	/**
	@ brief: 加密文件
	@ param[in]  symKey  加密秘钥
	@ param[in]  srcFilePath  源文件路径
	@ param[in]  callback 回调函数 (返回加密状态和加密后文件路径)
	@ return void
	*/
	void SecEncryptFile(const std::string &symKey,
		const std::string &srcFilePath,
		ReturnFunc callback);

	/**
	@ brief: 解密文件
	@ param[in] symKey  加密秘钥
	@ param[in] encFilePath  加密文件路径
	@ param[in] callback 回调函数 (返回解密状态和解密后文件路径)
	@ return void
	*/
	void SecDecryptFile(const std::string &symKey,
		const std::string &encFilePath,
		ReturnFunc callback);


	/***************************临时方案：提供对称加解密接口****************************/

	/**
	@ brief: 对称加密接口
	@ param[in]  data   原始数据
	@ param[out] enData 加密数据
	@ return int8_t 0：加密成功; 1：加密失败;
	*/
	int8_t SymEncrypt(const std::string &data/*in*/,
		std::string &enData/*out*/);

	/**
	@ brief: 对称解密接口
	@ param[in]  enData 加密数据
	@ param[out] data   原始数据
	@ return bool true：解密成功/false：解密失败
	*/
	bool SymDecrypt(const std::string &enData/*in*/,
		std::string &data/*out*/);

private:
	Private *_d;
};
	
}

#endif//KOAL_SECAGENT_H