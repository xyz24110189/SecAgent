#include "utils.h"
#include <time.h>
#include <fstream>
#include <regex>
#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#include <direct.h>
#else
#include <sys/time.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#endif

#define MSECS_PER_HOUR 3600000
#define MSECS_PER_MIN 60000

static inline unsigned int msecsFromDecomposed(int hour, int minute, int sec, int msec = 0)
{
	return MSECS_PER_HOUR * hour + MSECS_PER_MIN * minute + 1000 * sec + msec;
}

static inline uint64_t julianDayFromGregorianDate(int year, int month, int day)
{
	// Gregorian calendar starting from October 15, 1582
	// Algorithm from Henry F. Fliegel and Thomas C. Van Flandern
	return (1461 * (year + 4800 + (month - 14) / 12)) / 4
		+ (367 * (month - 2 - 12 * ((month - 14) / 12))) / 12
		- (3 * ((year + 4900 + (month - 14) / 12) / 100)) / 4
		+ day - 32075;
}

namespace koal {

namespace utils {

void Sleep(int32_t second)
{
#ifdef _WIN32
	::Sleep(second * 1000);
#else
	::sleep(second);
#endif

}

uint64_t GetCurentMs()
{
#ifdef _WIN32
	SYSTEMTIME st;
	memset(&st, 0, sizeof(SYSTEMTIME));
	GetSystemTime(&st);

	return msecsFromDecomposed(st.wHour, st.wMinute, st.wSecond, st.wMilliseconds) +
		uint64_t(julianDayFromGregorianDate(st.wYear, st.wMonth, st.wDay)
			- julianDayFromGregorianDate(1970, 1, 1)) * uint64_t(86400000);
#else
	struct timeval tv;
	gettimeofday(&tv, 0);
	return int64_t(tv.tv_sec) * 1000 + tv.tv_usec / 1000;
#endif
}

std::string GetApplicationPath()
{
	std::string result(MAX_PATH, '\0');
	char *ptr = &result[0];
#ifdef _WIN32
	GetModuleFileName(NULL, ptr, MAX_PATH);
#elif __linux__
	ssize_t count = readlink("/proc/self/exe", ptr, PATH_MAX);
#endif // _WIN32
	return result.substr(0, result.find_last_of("/\\") + 1);
}

std::string RandomString(int32_t len)
{
	srand(time(0));
	std::string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string newstr;
	int pos;
	while (newstr.size() != len) {
		pos = ((rand() % (str.size() - 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

bool PathExist(const char *pathname)
{
#ifndef _WIN32
	if (-1 != access(pathname, 0))
#else
	if (-1 != _access(pathname, 0))
#endif
		return true;
	return false;
}


bool CreateDir(const char *path)
{
	if (PathExist(path))
		return true;

	char tmpPath[MAX_PATH] = "";
	const char* pCur = path;
	memset(tmpPath, 0, sizeof(tmpPath));
	int pos = 0;
	while (*pCur++ != '\0') {
		tmpPath[pos++] = *(pCur - 1);
		if (tmpPath[0] == '\0') {
			return false;
		}
		if (*pCur == '/' || *pCur == '\0') {
			if (!PathExist(tmpPath)) {
#ifndef _WIN32
				if (mkdir(tmpPath, 0755) == -1)
					return false;
#else
				if (_mkdir(tmpPath) == -1)
					return false;
#endif
			}
		}
	}
	return true;
}

bool KCopyFile(const char *srcFile, const char *destFile)
{
	std::ifstream src(srcFile, std::ios::binary);
	std::ofstream dest(destFile, std::ios::binary);
	dest << src.rdbuf();
	return src && dest;
}

bool IsBase64(const std::string &content)
{
	static std::regex base64Regex("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
		std::regex_constants::ECMAScript | std::regex_constants::icase);

	if (!std::regex_match(content, base64Regex))
	{
		return false;
	}

	return true;
	/*
	size_t firstPaddingChar = content.find_first_of('=');
	return firstPaddingChar == std::string::npos
		|| firstPaddingChar == size - 1
		|| (firstPaddingChar == size - 2 && content[size - 1] == '=');
	*/
}

}
}