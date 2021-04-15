#ifndef KOAL_UTILS_H
#define KOAL_UTILS_H

#include <stdint.h>
#include <string>

namespace koal {

namespace utils {

	/**
	@ brief: 睡眠等待
	@ param[in] second 秒
	@
	*/
	void Sleep(int32_t second);

	/**
	@ brief: 获取当前时间(毫秒)
	@ return uint64_t  当前时间(毫秒)
	*/
    uint64_t GetCurentMs();

	/**
	@ brief: 获取程序执行目录
	@ return string 返回路径
	*/
	std::string GetApplicationPath();

	/**
	@ brief: 生成随机数
	@ param[in] len  随机数长度
	@ return std::string  返回随机数
	*/
    std::string RandomString(int32_t len);

	/**
	@ brief: 判断路径是否存在
	@ param[in] pathname 路径名
	@ return bool  true:存在/false:失败
	*/
	bool PathExist(const char *pathname);

	/**
	@ brief: 创建路径
	@ param[in] path  路径名
	@ return bool true:成功/false:失败
	*/
	bool CreateDir(const char *path);

	/**
	@ brief: 拷贝文件
	@ param[in]  srcFile 源文件
	@ param[out] destFile 目标文件
	*/
	bool KCopyFile(const char *srcFile, const char *destFile);

	/**
	@ brief: 判断是否为base64编码
	@ param[in]  content 内容
	@ param[out] bool true: base64编码/false: 非base64编码
	*/
	bool IsBase64(const std::string &content);
}

}

#endif//KOAL_UTILS_H