#ifndef THIS_IS_PKIADAPTER_HEADER_20191210
#define THIS_IS_PKIADAPTER_HEADER_20191210

#include "agentCommon.h"

#define SAR_OK                      0x00000000    //成功
#define SAR_FAIL                    0x0A000001    //失败

#ifdef SKF_BLOB_DEFINE	//如果外部调用程序已经此结构体，则通过此宏定义来屏蔽掉此结构体

#define ECC_MAX_XCOORDINATE_BITS_LEN 512        //ECC算法X座标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512        //ECC算法Y座标的最大长度
#define ECC_MAX_MODULUS_BITS_LEN     512        //ECC算法模数的最大长度

#define MAX_RSA_MODULUS_LEN         256         //RSA算法模数的最大长度
#define MAX_RSA_EXPONENT_LEN        4           //RSA算法指数的最大长度

#pragma pack(1)

///ECC签名数据结构
typedef struct stECCSIGNATUREBLOB{
    unsigned char r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char s[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

///RSA公钥数据结构
typedef struct stRSAPUBLICKEYBLOB{
    unsigned int AlgID;
    unsigned int BitLen;
    unsigned char Modulus[MAX_RSA_MODULUS_LEN];
    unsigned char PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

///ECC公钥数据结构
typedef struct stECCPUBLICKEYBLOB{
    unsigned int  BitLen;
    unsigned char   XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char   YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;


#pragma pack()
#endif

/**
 * @param url 访问key的设备路径
 * @param pbData 摘要数据
 * @param ulDataLen 摘要数据长度
 * @param pbSignature 签名数据
 * @param pulSignLen 签名数据的长度
 * @return 0表示成功，非0表示失败
 */
EXPORT_PKIAGENT unsigned int rsaSignData(char *url, unsigned char *pbData, unsigned int ulDataLen,
    unsigned char *pbSignature, unsigned int *pulSignLen);

/**
 * @param url 访问key的设备路径
 * @param pbData 摘要数据
 * @param ulDataLen 摘要数据长度
 * @param pSignature 签名数据
 * @return 0表示成功，非0表示失败
 */
EXPORT_PKIAGENT unsigned int eccSignData(char *url, unsigned char *pbData, unsigned int ulDataLen, PECCSIGNATUREBLOB pSignature);

/**
 * @param url 访问key的设备路径
 * @param bSignFlag 签名：1 ，加密：0
 * @param pbBlob 公钥
 * @param pulBlobLen 公钥长度
 * @return 0表示成功，非0表示失败
 */
EXPORT_PKIAGENT unsigned int exportPublicKey(char *url, int bSignFlag, unsigned char* pbBlob, unsigned int* pulBlobLen);

/**
 * @param url 访问key的设备路径
 * @param pRSAPubKeyBlob RSA公钥
 * @param pbData 摘要原文
 * @param ulDataLen 摘要长度
 * @param pbSignature 签名数据
 * @param ulSignLen RSA签名数据长度
 * @return 0表示成功，非0表示失败
 */
EXPORT_PKIAGENT unsigned int rsaVerify(
    char *url, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
    unsigned char *pbData, unsigned int ulDataLen, 
    unsigned char *pbSignature, unsigned int ulSignLen);

/**
 * @param url 访问key的设备路径
 * @param pECCPubKeyBlob ECC公钥
 * @param pbData 摘要原文
 * @param ulDataLen 摘要长度
 * @param pSignature ECC签名数据
 * @return 0表示成功，非0表示失败
 */
EXPORT_PKIAGENT unsigned int eccVerify(
    char *url, ECCPUBLICKEYBLOB* pECCPubKeyBlob,
    unsigned char *pbData, unsigned int ulDataLen, 
    PECCSIGNATUREBLOB pSignature);

#endif