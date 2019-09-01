#include "Enclave_t.h"

#include "sgx_trts.h"
#include <cstring>
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "Enclave.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "enclave_t.h" 
#include <string.h> 
#include <ctype.h>
#include <stdlib.h>
#define KEY_LEN  16
#define IV_LEN   12
#define GMAC_LEN 16

const char * path = "encryptcontext";

uint8_t gmac_out[16];
const uint8_t key[16] = { '1' };

typedef struct encrypt_ctx
{
	uint8_t key[KEY_LEN];
	uint8_t iv[IV_LEN];
	uint8_t gmac[GMAC_LEN];
}encrypt_ctx;

encrypt_ctx ctx;

/*
* print function here invokes the ocall function to print the contents of the buffer.
*/
void printf(const char *fmt, ...)
{
	char buf[BUF_SIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUF_SIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}


/* ecall_array_in_out:
*   arr[] will be allocated inside the enclave, content of arr[] will be copied either.
*   After ECALL returns, the results will be copied outside of the enclave.
*/
void ecall_array_in_out(int arr[4])
{
	for (int i = 0; i < 4; i++) {
		assert(arr[i] == i);
		arr[i] = (3 - i);
	}
	size_t n = 4, m = 6;
	double src[] = {
		1. , 2. , 3. , 4. , 5. , 6. ,
		7. , 8. , 9. , 10., 11., 12.,
		13., 14., 15., 16., 17., 18.,
		19., 20., 21., 22., 23., 24.
	};

	//ocall_dimatcopy('R','T', 3, 4, 1, src, 6, 6, n*m);

	uint32_t length = 16;
	uint8_t secret(length);
	uint32_t size = sgx_calc_sealed_data_size(0, sizeof(secret));
	uint8_t sealeddata(size);
	uint32_t ret = 0;
	uint8_t unsecret[16];
	ret = sgx_read_rand(&secret, 16);

	ret = sgx_seal_data(0, NULL,
		sizeof(secret), (uint8_t *)secret,
		size, (sgx_sealed_data_t *)sealeddata);
	ret = sgx_unseal_data((const sgx_sealed_data_t*)sealeddata, NULL, 0,
		(uint8_t*)unsecret, &length);
	int i = 0;
	ocall_print_uint(&secret, 16);
	ocall_print_uint((uint8_t*)sealeddata, size);

	uint8_t love[8] = { 'm', 'e', 'n', 'g', 'j', 'i', 'a', 'n' };
	uint32_t loveec[8];
	uint8_t iv[12] = { 0 };
	uint8_t mac_out[16];
	ret = sgx_rijndael128GCM_encrypt(
		NULL,
		&secret,
		loveec[0],
		&love[0],
		&iv[0],
		12,
		NULL,
		0,
		&mac_out
	);
	ocall_print_uint(love, 8);
	ocall_print_uint32(loveec, 8);

	uint8_t delove[8];
	//ocall_print_uint(secret, 16);
	ret = sgx_rijndael128GCM_decrypt(
		NULL,
		&secret,
		loveec[0],
		&delove[0],
		&iv[0],
		12,
		NULL,
		0,
		&mac_out
	);
	ocall_print_uint(delove, 8);
}


/*here we have defined an ecall function for file encryption
the paramenter of this function are
* crypt: encrypted file buffer
* plain: Plain text buffer
* size:  plain size
*/

void ecall_encrypt(uint8_t *plain, uint8_t *crypt, size_t size)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	uint8_t iv[12] = { 0 };
	uint8_t mac_out[16];
	ret = sgx_rijndael128GCM_encrypt(
		&key,
		plain,
		size,
		crypt,
		&iv[0],
		12,
		NULL,
		0,
		&gmac_out
	);

}

/*here we have defined an ecall function for file decryption
the paramenter of this function are
* crypt: encrypted file buffer
* plain: Plain text buffer
* size:  crypt size
*/
void ecall_decrypt(uint8_t *crypt, uint8_t *plain, size_t size)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	uint8_t iv[12] = { 0 };
	uint8_t mac_out[16];
	ret = sgx_rijndael128GCM_decrypt(
		&key,
		crypt,
		size,
		plain,
		&iv[0],
		12,
		NULL,
		0,
		&gmac_out
	);

}


//generating AES encryption key and storing it into the buffer

void generate_key(uint8_t * key, size_t size)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = sgx_read_rand(key, size);
}

/*enerating AES encryption key and storing it into the buffer
*/
void generate_iv(uint8_t * iv, size_t size)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = sgx_read_rand(iv, size);
}

//initialize encrypt context
void encrypt_ctx_init()
{
		if (KEY_LEN != IV_LEN)
	{
		generate_iv(ctx.iv, IV_LEN);
		generate_key(ctx.key, KEY_LEN);
		for (int i = 0; i < GMAC_LEN; ++i)
		{
		ctx.gmac[i] = 0;
	}
		encrypt_ctx_seal();
	}
	else {
		encrypt_ctx_unseal();
	}
	}

//seal context to disk file

void encrypt_ctx_seal()
{
uint32_t ret = 0;
size_t size = sgx_calc_sealed_data_size(0, sizeof(ctx));
uint8_t * temp = (uint8_t *)malloc(sizeof(ctx));
uint8_t * sealeddata = (uint8_t *)malloc(size * sizeof(uint8_t));
memcpy(temp, &ctx, sizeof(ctx));
ret = sgx_seal_data(
	0,
	NULL,
	sizeof(ctx),
	(uint8_t *)temp,
	size,
	(sgx_sealed_data_t *)sealeddata
);

	ocall_save_ctx(path, sealeddata, size);
}

//unseal context from disk file

void encrypt_ctx_unseal()
{
	uint32_t length = 16;
	uint32_t ret = 0;
	size_t size = sgx_calc_sealed_data_size(0, sizeof(ctx));
	uint8_t * data = (uint8_t *)malloc(size * sizeof(uint8_t));
	uint8_t * temp = (uint8_t *)malloc(sizeof(ctx));

//get secret from disk file
	ocall_get_secret(path, data, size);

	ret = sgx_unseal_data(
	(const sgx_sealed_data_t*)data,
	NULL,
	0,
	temp,
	&length
);
memcpy(&ctx, temp, sizeof(ctx));
}

void enclaveChangeBuffer(char *buf, size_t len)
{
	const char *secret = "Hello Enclave";
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
	else {
		memcpy(buf, "false", strlen("false") + 1);
	}
} 
