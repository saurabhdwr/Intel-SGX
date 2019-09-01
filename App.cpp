#define ENCLAVE_FILE "Enclave.signed.dll"
#define MAX_BUF_LEN 100
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "stdio.h"
#include <string>
int main()
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

	// Enclave calls will execute here
	printf("\n App: Buffertests:\n");

	// Change the buffer in the enclave

	printf("App: Buffer before ECALL: %s\n", buffer);
	enclaveChangeBuffer(eid, buffer, MAX_BUF_LEN);
	printf("App; Buffer after ECALL %s\n", buffer);

	// Destroy the Enclave when the execution of ECALL is completed
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		printf("\nApp: error, failed to destroy enclave. \n");
	getchar();
	return 0;
}
