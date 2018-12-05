#include <string.h>
#include "stdio.h"
#include "stdlib.h"
#include "crypto.h"
#include "des.h"
#include "md5.h"


static void printHex(unsigned char *data , int len){
	int i = 0;
	for(i = 0; i < len; i++){
		//printf("%02X ",data[i]);
		printf("%02x",data[i]);
	}
	printf("\n");
}


static unsigned char* pack_padding_pkcs5(const unsigned char in[], int *len){
	unsigned char paddNum = 8 - *len % 8;
    unsigned char *data = (unsigned char *)malloc(*len + paddNum);
	int i = 0;
    memset(data, 0, *len + paddNum);
    memcpy(data, in, *len);
    for (i = 0; i < paddNum; i++) {
        data[*len + i] = paddNum;
    }
	*len = *len + paddNum;
	return data;
}

static unsigned char* unpack_padding_pkcs5(const unsigned char in[], int *len){
	unsigned char paddNum = in[*len - 1];
	if(paddNum > 8){
		*len = 0;
		return NULL;
	}
	*len = *len + paddNum;
	
	unsigned char *data = (unsigned char *)malloc(*len);
	int i = 0;
    memset(data, 0, *len);
    memcpy(data, in, *len );
	return data;
}


CRYPTO_RESULT des_encode(CRYPTO_TYPE type, const unsigned char key[], unsigned char keyLen, const unsigned char vi[8], const unsigned char in[],unsigned char **out,int *len){
	unsigned char *data = pack_padding_pkcs5(in,len);
	*out = (unsigned char *)malloc(*len); 
	if(type == DES_ECB || type == DES_CBC){
		mbedtls_des_context context;
		mbedtls_des_init(&context);
		mbedtls_des_setkey_enc(&context, key);
		if(type == DES_ECB){
			int i = 0;
			int num = *len / 8;
			for(i = 0; i < num; i++){
				mbedtls_des_crypt_ecb(&context, data + i * 8, *out + i * 8);
			}
		}else{
			unsigned char v[8] = {0};
			memcpy(v,vi,8);
			mbedtls_des_crypt_cbc(&context,MBEDTLS_DES_ENCRYPT,*len, v, data, *out);
		}

	}else if(type == DES3_ECB || type == DES3_CBC){
		mbedtls_des3_context context;
		if(keyLen != 8 && keyLen != 16 && keyLen != 24){
			return RESULT_ERROR;
		}
		unsigned char k[24] = {0};
		memcpy(k,key,keyLen);
		
		mbedtls_des3_init(&context);
		mbedtls_des3_set3key_enc(&context, k);
		if(type == DES3_ECB){
			int i = 0;
			int num = *len / 8;
			for(i = 0; i < num; i++){
				mbedtls_des3_crypt_ecb(&context, data + i * 8, *out + i * 8);
			}
		}else{
			unsigned char v[8] = {0};
			memcpy(v,vi,8);
			mbedtls_des3_crypt_cbc(&context,MBEDTLS_DES_ENCRYPT,*len, v, data, *out);
		}
	}
	free(data);
	return RESULT_OK;
}



CRYPTO_RESULT des_decode(CRYPTO_TYPE type, const unsigned char key[], unsigned char keyLen, const unsigned char vi[8], const unsigned char in[],unsigned char **out,int *len){
	
	if(*len % 8){
		return RESULT_ERROR;
	}
	unsigned char *data = (unsigned char *)malloc(*len); 
	if(type == DES_ECB || type == DES_CBC){
		mbedtls_des_context context;
		mbedtls_des_init(&context);
		mbedtls_des_setkey_dec(&context, key);
		if(type == DES_ECB){
			int i = 0;
			int num = *len / 8;
			for(i = 0; i < num; i++){
				mbedtls_des_crypt_ecb(&context, in + i * 8, data + i * 8);
			}
		}else{
			unsigned char v[8] = {0};
			memcpy(v,vi,8);
			mbedtls_des_crypt_cbc(&context,MBEDTLS_DES_DECRYPT,*len, v, in, data);
		}

	}else if(type == DES3_ECB || type == DES3_CBC){
		mbedtls_des3_context context;
		if(keyLen != 8 && keyLen != 16 && keyLen != 24){
			return RESULT_ERROR;
		}
		unsigned char k[24] = {0};
		memcpy(k,key,keyLen);
		
		mbedtls_des3_init(&context);
		mbedtls_des3_set3key_dec(&context, k);
		if(type == DES3_ECB){
			int i = 0;
			int num = *len / 8;
			for(i = 0; i < num; i++){
				mbedtls_des3_crypt_ecb(&context, in + i * 8, data + i * 8);
			}
		}else{
			unsigned char v[8] = {0};
			memcpy(v,vi,8);
			mbedtls_des3_crypt_cbc(&context,MBEDTLS_DES_DECRYPT,*len, v, in, data);
		}
	}
	*out = unpack_padding_pkcs5(data,len);
	free(data);
	if(*len == 0){
		return RESULT_ERROR;
	}
	return RESULT_OK;
}


CRYPTO_RESULT md5(MD5_RESULT_TYPE type, const unsigned char in[],unsigned char **out,int *len){
	unsigned char md5_str[16] = {0};
	int i = 0;
	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context,(unsigned char *)in,*len);
	MD5Final(&context,md5_str);
	if(type == RESULT_TYPE_BIN){
		*out = (unsigned char *)malloc(16);
		memcpy(*out,md5_str,16);
		*len = 16;
		return RESULT_OK;
	}
	*out = (unsigned char *)malloc(33);
	for(i=0;i<16;i++) {
		if(type == RESULT_TYPE_STR_UPPER){
			sprintf(*out + (i * 2),"%02X",md5_str[i]);
		}else{
			sprintf(*out + (i * 2),"%02x",md5_str[i]);
		}
	}
	
	*len = 32;
	return RESULT_OK;
}


int main_test() {

	unsigned char* res, *res2;
	int len;

	printf("=====================DES ECB==================\n");
	len = 8;
	if(des_encode(DES_ECB,"12345678",8,NULL,"12345678",&res,&len) == RESULT_OK){
		printf("DES ECB ENCODE:");
		printHex(res,len);
		if(des_decode(DES_ECB,"12345678",8,NULL,res,&res2,&len) == RESULT_OK){
			printf("DES ECB DECODE:%s\n",res2);
			free(res2);
		}else{
			printf("=====================DES ECB DECODE ERROR==================\n");
		}
		free(res);
	}else{
		printf("=====================DES ECB ENCODE ERROR==================\n");
	}

	
	printf("=====================DES CBC==================\n");
	len = 8;
	if(des_encode(DES_CBC,"12345678",8,"12345678","12345678",&res,&len) == RESULT_OK){
		printf("DES CBC ENCODE:");
		printHex(res,len);
		if(des_decode(DES_CBC,"12345678",8,"12345678",res,&res2,&len) == RESULT_OK){
			printf("DES CBC DECODE:%s\n",res2);
			free(res2);
		}else{
			printf("=====================DES CBC DECODE ERROR==================\n");
		}
		free(res);
	}else{
		printf("=====================DES CBC ERROR==================\n");
	}


	
	printf("=====================3DES ECB==================\n");
	len = 10;
	if(des_encode(DES3_ECB,"1234567812345678",16,NULL,"1234567890",&res,&len) == RESULT_OK){
		printf("3DES ECB ENCODE:");
		printHex(res,len);
		if(des_decode(DES3_ECB,"1234567812345678",16,NULL,res,&res2,&len) == RESULT_OK){
			printf("3DES ECB DECODE:%s\n",res2);
			free(res2);
		}else{
			printf("=====================DES ECB DECODE ERROR==================\n");
		}
		free(res);
	}else{
		printf("=====================3DES ECB ERROR==================\n");
	}
	


	
	printf("=====================3DES CBC==================\n");
	len = 10;
	if(des_encode(DES3_CBC,"1234567812345678",16,"12345678","1234567890",&res,&len) == RESULT_OK){
		printf("3DES CBC ENCODE:");
		printHex(res,len);
		if(des_decode(DES3_CBC,"1234567812345678",16,"12345678",res,&res2,&len) == RESULT_OK){
			printf("3DES CBC DECODE:%s\n",res2);
			free(res2);
		}else{
			printf("=====================DES ECB DECODE ERROR==================\n");
		}
		free(res);
	}else{
		printf("=====================3DES CBC ERROR==================\n");
	}
	
	
	printf("=====================MD5==================\n");
	len = 10;
	md5(RESULT_TYPE_BIN, "1234567890", &res, &len);
	printf("MD5 BIN:");
	printHex(res,len);
	free(res);
	
	len = 10;
	md5(RESULT_TYPE_STR_UPPER, "1234567890", &res, &len);
	printf("MD5 HEX:%s\n",res);
	free(res);
	
	len = 10;
	md5(RESULT_TYPE_STR_LOWER, "1234567890", &res, &len);
	printf("MD5 HEX:%s\n",res);
	free(res);
	
    return 0;
}
#include "des.h"
