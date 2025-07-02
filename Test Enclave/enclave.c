//*********************************************************
//
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
// IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
// PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/*
    Defines the code that will be loaded into the VBS enclave.
--*/

#include "precomp.h"

// VBS enclave configuration

const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    IMAGE_ENCLAVE_POLICY_DEBUGGABLE,    // DO NOT SHIP DEBUGGABLE ENCLAVES TO PRODUCTION
    0,
    0,
    0,
    { 0xFE, 0xFE },    // family id
    { 0x01, 0x01 },    // image id
    0,                 // version
    0,                 // SVN
    0x10000000,        // size
    16,                // number of threads
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};

ULONG InitialCookie;
ProtectedBolbInfo *pbInfo;

BOOL
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD dwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (dwReason == DLL_PROCESS_ATTACH) {
        InitialCookie = 0xDADAF00D;
    }

    return TRUE;
}

void*
CALLBACK
CallEnclaveTest(
    _In_ void* Context
)
{
    WCHAR String[32];
    swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"CallEnclaveTest started");
    OutputDebugStringW(String);

    return (void*)((ULONG_PTR)(Context) ^ InitialCookie);
}
/*
// This function is a placeholder for creating a symmetric key.
PUCHAR CreateSymmetricKey() {
    // you would use BcryptOpenAlgorithmProvider to open an algorithm provider
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    LPCWSTR pszAlgId = BCRYPT_AES_ALGORITHM;
    LPCWSTR pszImplementation = NULL;
    ULONG dwFlags = 0;
	//if successful, hAlgorithm will be a handle to the algorithm provider(return STATUS_SUCCESS(0x00000000))
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(hAlgorithm, pszAlgId, pszImplementation, dwFlags))) {
		return NULL; // Handle error appropriately
    }

	// You would typically use BCryptGenerateSymmetricKey to create a symmetric key
	BCRYPT_KEY_HANDLE phKey = NULL;
	PUCHAR pbKeyObject = NULL;
    ULONG cbKeyObject = 0;

	BCryptGenerateSymmetricKey(
		hAlgorithm,             // hAlgorithm
		phKey,                  // phKey
        pbKeyObject,                   // pbKeyObject
        cbKeyObject,                      // cbKeyObject
		NULL,                   // pbSecret
		0,                      // cbSecret
        pszAlgId                // pszAlgId
	); 
}


void*
CALLBACK
CallEncryptionTest(
    _In_ void* PlainText
)
{
	BcryptEncrypt(
			NULL,                   // hKey
			(PUCHAR)PlainText,     // pbInput
			(ULONG)strlen((char*)PlainText), // cbInput
			NULL,                   // pPaddingInfo
			NULL,                   // pbIV
			0,                      // cbIV
			NULL,                   // pbOutput
			0,                      // cbOutput
			NULL,                   // pcbResult
			BCRYPT_BLOCK_PADDING    // dwFlags
			);
}
*/
void*
CALLBACK
CallEnclaveSealData(
    _In_ void* msgData
)
{
	strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "CallEnclaveSealData started.\n");

    pbInfo = (ProtectedBolbInfo*)malloc(sizeof(ProtectedBolbInfo));
    // Check if memory allocation for pbInfo was successful  
    if (pbInfo == NULL) {
        ((MessageDataInfo*)msgData)->hr = E_OUTOFMEMORY; // Set error code in msgData
        strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "Memory allocation for pbInfo failed.\n");
        return E_FAIL;
    }
    else {
		memset(pbInfo, 0, sizeof(ProtectedBolbInfo)); // Initialize pbInfo to zero
    }
    
    size_t actualBolbSize = 256;
    pbInfo->protectedBlob = (char*)malloc(actualBolbSize);
    if (pbInfo->protectedBlob == NULL) {
        ((MessageDataInfo*)msgData)->hr = E_OUTOFMEMORY; // Set error code in msgData
        strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "Memory allocation for protectedBolb failed.\n");
        free(pbInfo);
        return E_FAIL;
    }
	pbInfo->protectedBlob[0] = '\0'; // Initialize protectedBlob to an empty string

    // Create a protected blob info structure to hold the sealed data.  
    pbInfo->hr = EnclaveSealData(
        ((MessageDataInfo*)msgData)->msg,               // DataToEncrypt  
        ((MessageDataInfo*)msgData)->msg_size,          // DataToEncryptSize  
        ENCLAVE_IDENTITY_POLICY_SEAL_SAME_AUTHOR,        // IdentityPolicy  
        ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG,        // RuntimePolicy  
        (PVOID)pbInfo->protectedBlob,                   // ProtectedBlob  
        BUFFER_SIZE,                                    // BufferSize  
        &(pbInfo->protectedBlobSize)                       // *ProtectedBlobSize  
    );

    //log
    strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "CallEnclaveSealData finished.\n");
    // Convert the protectedBlob to a string and append it to the log
    strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "pbInfo->protectedBlob: ");
    char* blobAddr = (char*)pbInfo->protectedBlob;
    strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, (blobAddr ? blobAddr : "NULL"));
	strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "\n");

    // Convert the protectedBlobSize to a string and append it to the log
    strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "pbInfo->protectedBolbSize: ");
    char bolbSize[10];       // 변환한 문자열을 저장할 배열
    sprintf_s(bolbSize, 10, "%d", pbInfo->protectedBlobSize);    // %d를 지정하여 정수를 문자열로 저장
	strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, bolbSize); 
    strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "\n");

    //test - put the protectedBolb values
    //((MessageDataInfo*)msgData)->protectedBlob = pbInfo->protectedBlob;
    // Ensure pbInfo->protectedBlob is not NULL before calling strcpy_s  
    if (pbInfo->protectedBlob != NULL) {
        strcpy_s(((MessageDataInfo*)msgData)->protectedBlob, sizeof(((MessageDataInfo*)msgData)->protectedBlob), pbInfo->protectedBlob);
    }
    else {
        strcat_s(((MessageDataInfo*)msgData)->log, LOG_SIZE, "pbInfo->protectedBlob is NULL, skipping strcpy_s.\n");
    }
    ((MessageDataInfo*)msgData)->protectedBlobSize = pbInfo->protectedBlobSize;

    // Return the result
    return (void*)pbInfo->hr;
}

void*
CALLBACK
CallEnclaveUnsealData(
    _In_ void* decryptedMsgData
) 
{
    ENCLAVE_IDENTITY sealingIdentity;
    UINT32 unsealingFlags = 0;

	//MessageDataInfo* tempData = (MessageDataInfo*)malloc(sizeof(MessageDataInfo));
    //// Check if memory allocation for pbInfo was successful  
    //if (tempData == NULL) {
    //    OutputDebugStringW(L"Memory allocation for pbInfo failed.\n");
    //    return E_FAIL;
    //}
    //else {
    //    memset(tempData, 0, sizeof(MessageDataInfo)); // Initialize tempData to zero
    //}
	//strcpy_s(tempData->msg, STR_SIZE, "nothing_vbsSide");
	//tempData->msg_size = strlen(tempData->msg);
	//tempData->log[0] = '\0'; // Initialize log to an empty string

    //log - check input
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "CallEnclaveUnsealData started.\n");
    strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "initial message: ");
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, ((MessageDataInfo*)decryptedMsgData)->msg);
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "\n");

    //check if pbInfo->protectedBlob is NULL
    if (pbInfo->protectedBlob == NULL) {
        strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "pbInfo->protectedBlob is NULL.\n");
    }

	HRESULT hr = EnclaveUnsealData(
		pbInfo->protectedBlob,          // ProtectedBlob  
		pbInfo->protectedBlobSize,      // ProtectedBlobSize  
        ((MessageDataInfo*)decryptedMsgData)->msg,           // DecryptedData
		BUFFER_SIZE,                    // BufferSize  
        &(((MessageDataInfo*)decryptedMsgData)->msg_size),      // *DecryptedDataSize  
		&sealingIdentity,            // *SealingIdentity
        &unsealingFlags              // *UnsealingFlags
	);

    //log - check decrypted result
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "CallEnclaveUnsealData finished.\n");
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "Decrypted message: ");
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, ((MessageDataInfo*)decryptedMsgData)->msg);
	strcat_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, "\n");

    ////copy
	//strcpy_s(((MessageDataInfo*)decryptedMsgData)->msg, STR_SIZE, tempData->msg);
	//((MessageDataInfo*)decryptedMsgData)->msg_size = tempData->msg_size;
    //strcpy_s(((MessageDataInfo*)decryptedMsgData)->log, LOG_SIZE, tempData->log);

    ////free
    //free(tempData);

    return (void*)hr;
}