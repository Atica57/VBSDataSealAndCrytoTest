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
    _In_ void* data
)
{
    MessageDataInfo* msgData = (MessageDataInfo*)data;
    
    pbInfo = (ProtectedBolbInfo*)malloc(sizeof(ProtectedBolbInfo));
    // Check if memory allocation for pbInfo was successful  
    if (pbInfo == NULL) {
        OutputDebugStringW(L"Memory allocation for pbInfo failed.\n");
        return NULL;
    }
    else {
		memset(pbInfo, 0, sizeof(ProtectedBolbInfo)); // Initialize pbInfo to zero
    }
    
    size_t actualBolbSize = 256;
    pbInfo->protectedBlob = malloc(actualBolbSize);
    if (pbInfo->protectedBolbSize == NULL) {
        OutputDebugStringW(L"Memory allocation for protectedBolb failed.\n");
        free(pbInfo);
        return NULL;
    }
    memset(pbInfo->protectedBlob, 0, actualBolbSize);

    // Create a protected blob info structure to hold the sealed data.  
    pbInfo->hr = EnclaveSealData(
        msgData->msg,           // DataToEncrypt  
        msgData->msg_size,      // DataToEncryptSize  
        ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,        // IdentityPolicy  
        ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG,        // RuntimePolicy  
        pbInfo->protectedBlob,                          // ProtectedBlob  
        BUFFER_SIZE,                                    // BufferSize  
        pbInfo->protectedBolbSize                       // *ProtectedBlobSize  
    );

    // Return the result
    if (pbInfo->hr == S_OK) {
        return (void*)pbInfo->hr;
        //return (void*)pbInfo;
    }
    else {
        return (void*)pbInfo->hr;
    }
}

void*
CALLBACK
CallEnclaveUnsealData(
    _In_ void* decryptedMsgData
) 
{
	//MessageDataInfo decryptedMsgData;
	HRESULT hr = EnclaveUnsealData(
		pbInfo->protectedBlob,          // ProtectedBlob  
		pbInfo->protectedBolbSize,      // ProtectedBlobSize  
        (PVOID)((MessageDataInfo*)decryptedMsgData)->msg,           // DecryptedData
		BUFFER_SIZE,                    // BufferSize  
        &(((MessageDataInfo*)decryptedMsgData)->msg_size),      // *DecryptedDataSize  
		NULL,                           // *SealingIdentity
        NULL                            // *UnsealingFlags
	);

    return (void*)hr;
}