#include "Enclave_t.h"

#include "sgx_trts.h"
#include <cstring>

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
