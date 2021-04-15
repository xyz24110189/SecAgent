#ifndef KOAL_COMMON_H
#define KOAL_COMMON_H

#include <stdint.h>
#include <string>
#include <functional>

#ifdef _WIN32
	#define SLASH "\\"
#else
	#define SLASH "/"
#endif

#define DB_PATH_NAME "database"
#define LOG_PATH_NAME "logs"
#define DB_NAME "secAgent.db"

#define ENCRYPT_PER_SIZE 1024 * 1024 * 16
#define DECRYPT_PER_SIZE ENCRYPT_PER_SIZE + 16
#define SYM_ENCRYPT_KEY "IeyQk9nGL21dWUzZ"

#define FREE_OBJECT(obj) \
	if (obj)			 \
	{					 \
		delete obj;		 \
		obj = NULL;		 \
	}	

#define K_DISABLE_COPY(Class) \
	Class(const Class &); \
	Class &operator=(const Class &);

typedef std::function<bool(const std::string &, const std::string &, std::string &)> DecryptionFunc;
typedef std::function<void(int8_t res, const std::string &)> ReturnFunc;

struct FileDecryptInfo
{
	std::string symKey;
	std::string inFilePath;
	DecryptionFunc decCallback;
	ReturnFunc RetCallback;
};

#endif//KOAL_COMMON_H