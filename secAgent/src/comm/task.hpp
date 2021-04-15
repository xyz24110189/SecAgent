#pragma once
#include "comm.h"

namespace koal
{

class ITask
{
public:
	virtual void Run() = 0;
};

template <typename T> 
class IBase : public ITask
{
public:
	IBase(T data) { _data = data; }
	~IBase() {}
	virtual void Run() {};

protected: 
	T _data;
};

class FileDecryption : public IBase<FileDecryptInfo>
{
public:
	FileDecryption(FileDecryptInfo data) : IBase(data) {}
	~FileDecryption() {}

	virtual void Run()
	{
		std::string outFilePath;
		bool bRet = _data.decCallback(_data.symKey, _data.inFilePath, outFilePath);
		_data.RetCallback(bRet, outFilePath);
	}
};

}


