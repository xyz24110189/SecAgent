#ifndef KOAL_SQLCIPHER_DB_H
#define KOAL_SQLCIPHER_DB_H

#include <string>

struct sqlite3;

namespace koal {

class SqlCipherDb 
{
public:
	static SqlCipherDb *GetInstance();

	bool InitDb(const std::string &appDir);
	bool InsertUserCert(const char *accid, const char *certPath);
	bool InsertKey(const char *accid, const char *symKey);
	bool UpdateKey(const char *accid, const char *symKey);
	bool UpdateEncKey(const char *accid, const char *symKey, const char *encSymKey);
	bool UpdateLastEncTime(const char *accid, int64_t curMs);
	bool QueryLastEncTime(const char *accid, int64_t &lastOperTime);
	bool QueryCertByAccid(const char *accid, std::string &certPath);
	bool QueryKeyByAccid(const char *accid, std::string &key);
	bool QueryExistByEncKey(const char *accid, const char *encKey);

protected:
	void CloseDb();
	bool CreateEncTable();
	bool CreatePubTable();
	bool IsTableExist(const char *tableName);

	static int CommCallback(void *param, int argc, char **argv, char **azColName);
	static int LastOperTimeCallback(void *param, int argc, char **argv, char **azColName);
	static int CertPathCallBack(void *param, int argc, char **argv, char **azColName);
	static int SymKeyCallBack(void *param, int argc, char **argv, char **azColName);
	static int IsEncKeyExistCallback(void *param, int argc, char **argv, char **azColName);
	static int IsTableExistCallback(void *param, int argc, char **argv, char **azColName);

private:
	explicit SqlCipherDb();
	~SqlCipherDb();

	sqlite3 *_db;
};

}

#endif//KOAL_SQLCIPHER_DB_H