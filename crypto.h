#ifndef __CRYPTO_H
#define __CRYPTO_H


typedef enum{
	DES_ECB =0,
	DES_CBC,
	DES3_ECB,
	DES3_CBC,
}CRYPTO_TYPE;


typedef enum{
	RESULT_TYPE_BIN =0,//bin类型
	RESULT_TYPE_STR_UPPER,//HEX大写字符串
	RESULT_TYPE_STR_LOWER,//HEX小写字符串
}MD5_RESULT_TYPE;


typedef enum{
	RESULT_OK = 0,
	RESULT_ERROR,
}CRYPTO_RESULT;
	

#ifdef __cplusplus
extern "C" {
#endif

/*
	DES 加密
	type[in]:加密方式
	key[in] 秘钥 des 固定8位 3des可为8位 16位 24位
	keyLen[in] 秘钥长度，des固定为8,3des可为8 16 24
	vi[in] 偏移   固定8位， CBC方式可用,ECB 为null
	in[in] 待加密数据
	out[out] 加密后数据(需要free)
	len[in/out] 传入待加密数据长度，传出加密后数据长度
	return 是否成功
*/
CRYPTO_RESULT des_encode(CRYPTO_TYPE type, const unsigned char key[], unsigned char keyLen, const unsigned char vi[8], const unsigned char in[],unsigned char **out,int *len);
	
	
/*
	DES 解密
	type[in]:解密方式
	key[in] 秘钥 des 固定8位 3des可为8位 16位 24位
	keyLen[in] 秘钥长度，des固定为8,3des可为8 16 24
	vi[in] 偏移	固定8位， CBC方式可用,ECB 为null
	in[in] 待解密数据
	out[out] 解密后数据(需要free)
	len[in/out] 传入待解密数据长度，传出解密后数据长度
	return 是否成功
*/
CRYPTO_RESULT des_decode(CRYPTO_TYPE type, const unsigned char key[], unsigned char keyLen, const unsigned char vi[8], const unsigned char in[],unsigned char **out,int *len);

/*
	MD5 摘要
	type[in]:结果方式
	in[in] 待摘要数据
	out[out] 摘要后数据(需要free)
	len[in/out] 传入待摘要数据长度，传出摘要后数据长度
	return 是否成功
*/

CRYPTO_RESULT md5(MD5_RESULT_TYPE type, const unsigned char in[],unsigned char **out,int *len);

/*
	BASE64编码
	type[in]:结果方式
	in[in] 待编码的数据
	out[out] 编码后数据(需要free)
	len[in/out] 传入编码要数据长度，传出编码后数据长度
	return 是否成功
*/

CRYPTO_RESULT base64_en(const unsigned char in[],unsigned char **out,int *len);

/*
	BASE64解码
	type[in]:结果方式
	in[in] 待解码的数据
	out[out] 解码后数据(需要free)
	len[in/out] 传入编码要数据长度，传出编码后数据长度
	return 是否成功
*/

CRYPTO_RESULT base64_de(const unsigned char in[],unsigned char **out,int *len);


#ifdef __cplusplus
}
#endif
#endif
