#include "..\Enclave\Enclave_t.h"
#define ENCLAVE_FILE "Enclave.signed.dll"
#define MAX_BUF_LEN 100
#include "sgx_urts.h"
#include <iostream>
#include <fstream>
#include <string.h>
#include <assert.h>
# define MAX_PATH 
#define FILENAME_MAX
#include "Enclave_u.h"
#include "stdio.h"
#include "sgx_tseal.h"
#include "sgx_uae_service.h"
#include <string>
#include "sgx_tcrypto.h"
#include <fstream>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <conio.h>
#include <iostream>
#include <pwd.h>
#include "App.h"
#include <unistd.h>
#include <sys/types.h>
using namespace std;
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* This is the list of error codes that is returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
	{
		SGX_ERROR_NDEBUG_ENCLAVE,
		"The enclave is signed as product enclave, and can not be created as debuggable enclave.",
		NULL
	},
};

/* Here we are checking for error conditions for loading enclaves */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}

/* These are the steps to be followed for initializing the enclave
*   1: saving the last transaction to try to retrieve the launch token
*   2: to initialize an enclave instance we will call the sgx_create_enclave function
*   3: save the launch token once it is updated
*/
int initialize_enclave(void)
{
	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: saving the last transaction to try to retrieve the launch token,in case if there is no token, then create a new one.
	*/

	/* try to save the token in the home directory */
	const char *home_dir = getpwuid(&getuid())->pw_dir;

	if (home_dir != NULL &&
		(strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
		/* compose the token path */
		strncpy_s(token_path, home_dir, strlen(home_dir));
		strncat_s(token_path, "/", strlen("/"));
		strncat_s(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	}
	else {
		/* if token path is too long or home directory is NULL */
		strncpy_s(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}

	/* Step 2: calling sgx_create_enclave function to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);

		if (fp != NULL) fclose(fp);
		return -1;
	}

	/* Step 3: save the launch token if it is updated */

	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	}

	/* here I have reopende the file with writing enabled */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* To prevent the buffer flow Proxy/Bridge will check the length and null-terminate
	* the input string.
	*/
	printf("%s", str);
}


void ocall_print_uint(uint8_t * u, size_t size)
{
	printf("Info: uint8_t*: ");
	for (int i = 0; i<size; i++)
	{
		if (i % 24 == 0)
			printf("\n");
		printf("%4d", (uint8_t) *(u + i));
	}
	printf("\n");
}

int encrypt_file(const char * path) {

	fstream file(path, ios::in | ios::out | ios::binary);
	int file_size = 0;
	int crypt_len = 0;


	if (file.is_open())
	{

		file.seekg(0, file.end);
		file_size = static_cast<int> (file.tellg());
		uint8_t * plain = new uint8_t[file_size];
		file.seekg(0, ios::beg);
		file.read(reinterpret_cast<char *>(plain), (streamsize)file_size);
		cout.write(reinterpret_cast<char*>(plain), file_size);
		uint8_t * crypt = (uint8_t*)malloc(sizeof(char)*file_size);
		crypt_len = file_size;
		ecall_encrypt(plain, crypt, file_size);
		file.seekg(0, ios::beg);
		file.write(reinterpret_cast<const char*>(crypt), (streamsize)crypt_len);
		free(plain);
		free(crypt);
		file.close();
	}
	cout << "encrypted the file" << endl;
}

int decrypt_file(const char * path)
{
	fstream file(path, ios::in | ios::out | ios::binary);
	int file_size = 0;
	int plain_len = 0;
	if (file.is_open())
	{

		file.seekg(0, file.end);
		file_size = static_cast<int> (file.tellg());
		uint8_t * crypt = new uint8_t[file_size];
		file.seekg(0, ios::beg);
		file.read(reinterpret_cast<char *>(crypt), (streamsize)file_size);
		uint8_t * plain = (uint8_t*)malloc(sizeof(char)*file_size);
		plain_len = file_size;
		ecall_decrypt(crypt, plain, file_size);
		file.seekg(0, ios::beg);
		cout.write(reinterpret_cast<char *>(plain), file_size);
		file.write(reinterpret_cast<const char*>(plain), (streamsize)plain_len);
		free(plain);
		free(crypt);
		file.close();
	}
	cout << "decrypted the file" << endl;
}


void ocall_save_ctx(const char * path, uint8_t *data, size_t size)
{
	fstream file(path, ios::in | ios::out | ios::binary);
	int file_size = 0;

	if (file.is_open())
	{
		file.seekg(0, ios::beg);
		file.write(reinterpret_cast<char *>(data), (streamsize)size);

		file.close();
	}

	cout << "seal secret from enclave --> disk file" << endl;
}

void ocall_get_secret(const char * path, uint8_t *data, size_t size)
{
	fstream file(path, ios::in | ios::out | ios::binary);
	int file_size = 0;

	if (file.is_open())
	{

		file.seekg(0, file.end);
		file_size = static_cast<int> (file.tellg());
		file.seekg(0, ios::beg);
		file.read(reinterpret_cast<char *>(data), (streamsize)file_size);

		file.close();
	}
	cout << "getting secret from disk file --> enclave" << endl;
}


int main(int argc, char * argv[])
{
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

	if (ret != SGX_SUCCESS) {
		printf("\n App: error %#x, failed to create enclave. \n", ret);
	}

	// A bunch of Enclave calls will happen here
	printf("\n App: Buffertests:\n");

	// Change the buffer in the enclave

	printf("App: Buffer before ECALL: %s\n", buffer);
	enclaveChangeBuffer(eid, buffer, MAX_BUF_LEN);
	printf("App; Buffer after ECALL %s\n", buffer);

	// Destroy the Enclave when all ECALL are finished
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		printf("\nApp: error, failed to destroy enclave. \n");
	getchar();
	return 0;
	const char* filename = "test.txt";
	encrypt_file(filename);
	decrypt_file(filename);
}
