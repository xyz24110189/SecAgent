#include "sqlCipherDb.h"
#include "comm/utils.h"
#include "comm/comm.h"
#include <stdlib.h>
#include <plog/Log.h>
#include <sqlite/sqlite3.h>

namespace koal {

SqlCipherDb::SqlCipherDb() : _db(NULL)
{

}

SqlCipherDb::~SqlCipherDb()
{
	CloseDb();
}

SqlCipherDb *SqlCipherDb::GetInstance()
{
	static SqlCipherDb inst;
	return &inst;
}


bool SqlCipherDb::InitDb(const std::string &appDir)
{
	int rc;

	rc = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
	if (rc) {
		LOG_ERROR << "Can't config SQLITE_CONFIG_SERIALIZED param";
		return false;
	}

	std::string dbPath = appDir + SLASH + DB_PATH_NAME;
	utils::CreateDir(dbPath.data());
	dbPath += SLASH;
	dbPath += DB_NAME;
	rc = sqlite3_open(dbPath.c_str(), &_db);

	if (rc) {
		LOG_ERROR << "Can't open database: " << sqlite3_errmsg(_db);
		return false;
	}
	else {
		LOG_INFO << "Opened database successfully.";

		std::string key = "secAgent%^&*$#@!";
		rc = sqlite3_key(_db, key.data(), key.length());
		if (rc){
			LOG_ERROR << "Can't encrypt database: %s\n", sqlite3_errmsg(_db);
		}

		bool bRet = CreateEncTable();
		if (!bRet)
		{
			utils::Sleep(2);
			if (!CreateEncTable())
			{
				sqlite3_close(_db);
				return false;//exit(-1);
			}
		}

		bRet = CreatePubTable();
		if (!bRet)
		{
			utils::Sleep(2);
			if (!CreatePubTable())
			{
				sqlite3_close(_db);
				return false;//exit(-1);
			}
		}
		return true;
	}
}

void SqlCipherDb::CloseDb()
{
	LOG_INFO << "SqlCipherDb::CloseDb begin...";
	if (_db)
	{
		sqlite3_close(_db);
		_db = NULL;
	}
	LOG_INFO << "SqlCipherDb::CloseDb end...";
}

bool SqlCipherDb::CreateEncTable()
{
	if (IsTableExist("SYMENCRYPT")) return true;

	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/* Create SQL statement */
	char *sql = "CREATE TABLE SYMENCRYPT(" \
		"ID INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL," \
		"USERID                             TEXT NOT NULL," \
		"SYMKEY                             TEXT," \
		"LASTOPERTIME                       INTEGER," \
		"UNIQUE(USERID))";

	/* Execute SQL statement */
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		LOG_ERROR << "CreateEncTable SQL error: " << zErrMsg;
		sqlite3_free(zErrMsg);
		bRet = false;
	}
	else {
		LOG_INFO << "CreateEncTable Operator Done successfully.";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::CreatePubTable()
{
	if (IsTableExist("PUBENCRYPT")) return true;

	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/* Create SQL statement */
	char *sql = "CREATE TABLE PUBENCRYPT(" \
		"ID INTEGER PRIMARY KEY AUTOINCREMENT  NOT NULL," \
		"USERID                             TEXT NOT NULL," \
		"CERTPATH                           TEXT NOT NULL," \
		"ENCSYMKEY                          TEXT," \
		"SYMKEY                             TEXT," \
		"UNIQUE(USERID))";

	/* Execute SQL statement */
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		LOG_ERROR << "CreatePubTable SQL error: " << zErrMsg;
		sqlite3_free(zErrMsg);
		bRet = false;
	}
	else {
		LOG_INFO << "CreatePubTable Operator Done successfully.";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::IsTableExist(const char *tableName)
{
	char *zErrMsg = 0;
	int rc;
	bool hasTable = false;

	/* Create SQL statement */
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", tableName);

	/* Execute SQL statement */
	rc = sqlite3_exec(_db, sql, IsTableExistCallback, (void*)&hasTable, &zErrMsg);

	if (rc != SQLITE_OK) {
		LOG_ERROR << "TableExistJudge SQL error:" << zErrMsg;
		sqlite3_free(zErrMsg);
		return false;
	}
	else {
		LOG_INFO << "TableExistJudge Operation done successfully";
		return hasTable;
	}

}

bool SqlCipherDb::InsertUserCert(const char *accid, const char *certPath)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "INSERT INTO PUBENCRYPT(USERID, CERTPATH) VALUES('%s', '%s')", accid, certPath);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "InsertUserCert SQL Excute Error: " << zErrMsg;
		bRet = false;
	} else {
		LOG_INFO << "InsertUserCert SQL Excute Success!";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::InsertKey(const char *accid, const char *symKey)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	int64_t curMs = utils::GetCurentMs();

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "INSERT INTO SYMENCRYPT(USERID, SYMKEY, LASTOPERTIME) VALUES('%s', '%s', '%lld')", accid, symKey, curMs);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "InsertKey SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "InsertKey SQL Excute Success!";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::UpdateKey(const char *accid, const char *symKey)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	int64_t curMs = utils::GetCurentMs();

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "UPDATE SYMENCRYPT SET SYMKEY='%s', LASTOPERTIME='%lld' WHERE USERID='%s'", symKey, curMs, accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "UpdateKey SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "UpdateKey SQL Excute Success!";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::UpdateEncKey(const char *accid, const char *symKey, const char *encSymKey)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "UPDATE PUBENCRYPT SET SYMKEY='%s', ENCSYMKEY=%s WHERE USERID='%s'",
		symKey, encSymKey, accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "UpdateEncKey SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "UpdateEncKey SQL Excute Success!";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::UpdateLastEncTime(const char *accid, int64_t curMs)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "UPDATE SYMENCRYPT SET LASTOPERTIME='%lld' WHERE USERID='%s'",
		curMs, accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CommCallback, 0, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "UpdateEncKey SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "UpdateEncKey SQL Excute Success!";
		bRet = true;
	}

	return bRet;
}

bool SqlCipherDb::QueryLastEncTime(const char *accid, int64_t &lastOperTime)
{
	char *zErrMsg = 0;
	int rc; 
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "SELECT LASTOPERTIME FROM SYMENCRYPT WHERE USERID='%s'", accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, LastOperTimeCallback, (void *)&lastOperTime, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "QueryLastEncTime SQL Excute Error: " << zErrMsg;
		bRet = false;
	} else {
		LOG_INFO << "QueryLastEncTime SQL Excute Success!";
		bRet = true;
	}

	return lastOperTime!= 0 && bRet;
}

bool SqlCipherDb::QueryCertByAccid(const char *accid, std::string &certPath)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "SELECT CERTPATH FROM PUBENCRYPT WHERE USERID='%s'", accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, CertPathCallBack, (void *)&certPath, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "QeuryCertByAccid SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "QeuryCertByAccid SQL Excute Success!";
		bRet = true;
	}

	return !certPath.empty() && bRet;
}

bool SqlCipherDb::QueryKeyByAccid(const char *accid, std::string &key)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "SELECT SYMKEY FROM SYMENCRYPT WHERE USERID='%s'", accid);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, SymKeyCallBack, (void *)&key, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "QueryKeyByAccid SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "QueryKeyByAccid SQL Excute Success!";
		bRet = true;
	}

	return !key.empty() && bRet;
}

bool SqlCipherDb::QueryExistByEncKey(const char *accid, const char *encKey)
{
	char *zErrMsg = 0;
	int rc;
	bool bRet;
	bool bExist = false;

	/*Create Sql statement*/
	char sql[BUFSIZ] = { 0 };
	sprintf(sql, "SELECT ENCSYMKEY FROM PUBENCRYPT WHERE USERID='%s' AND ENCSYMKEY='%s'", accid, encKey);

	/*Excute SQL statement*/
	rc = sqlite3_exec(_db, sql, IsEncKeyExistCallback, (void *)&bExist, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		LOG_ERROR << "QueryExistByEncKey SQL Excute Error: " << zErrMsg;
		bRet = false;
	}
	else {
		LOG_INFO << "QueryExistByEncKey SQL Excute Success!";
		bRet = true;
	}

	return bExist && bRet;
}

int SqlCipherDb::LastOperTimeCallback(void *param, int argc, char **argv, char **azColName)
{
	int64_t *lastTime = static_cast<int64_t *>(param);
	int i;
	for (i = 0; i < argc; i++) {
		LOG_INFO << "LastOperTimeCallback operation result = " << azColName[i] << " " << (argv[i] ? argv[i] : "NULL");
		*lastTime = atoll(argv[i]);
	}
	return 0;
}

int SqlCipherDb::CertPathCallBack(void *param, int argc, char **argv, char **azColName)
{
	std::string *certPath = static_cast<std::string *>(param);
	int i;
	for (i = 0; i < argc; i++) {
		LOG_INFO << "CertPathCallBack operation result = " << azColName[i] << " " << (argv[i] ? argv[i] : "NULL");
		*certPath = argv[i];
	}
	return 0;
}

int SqlCipherDb::SymKeyCallBack(void *param, int argc, char **argv, char **azColName)
{
	std::string *symKey = static_cast<std::string *>(param);
	int i;
	for (i = 0; i < argc; i++) {
		LOG_INFO << "SymKeyCallBack operation result = " << azColName[i] << " " << (argv[i] ? argv[i] : "NULL");
		*symKey = argv[i];
	}
	return 0;
}

int SqlCipherDb::CommCallback(void *param, int argc, char **argv, char **azColName)
{
	int i;
	for (i = 0; i < argc; i++) {
		LOG_INFO << "common operation result = " << azColName[i] << " " << (argv[i] ? argv[i] : "NULL");
	}
	return 0;
}

int SqlCipherDb::IsEncKeyExistCallback(void *param, int argc, char **argv, char **azColName)
{
	bool *hasEncKey = (bool *)param;

	if (argc > 0)
		*hasEncKey = true;

	LOG_INFO << "IsEncKeyExistCallback hasEncKey = " << *hasEncKey;
	return 0;
}

int SqlCipherDb::IsTableExistCallback(void *param, int argc, char **argv, char **azColName)
{
	bool *hasTable = (bool *)param;

	if (argc > 0)
		*hasTable = true;

	LOG_INFO << "TableExistCallback hasTable = " << *hasTable;
	return 0;
}


}