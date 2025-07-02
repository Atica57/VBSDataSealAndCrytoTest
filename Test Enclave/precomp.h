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

//Test Enclave header file

#pragma once

#define STR_SIZE 1024
#define BUFFER_SIZE 32'768
#define LOG_SIZE 100'000

#include <winenclave.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <malloc.h>
#include <bcrypt.h>

typedef struct {
    HRESULT hr;
    BYTE Report[BUFFER_SIZE];
    UINT32 ReportSize;
}ReportDataInfo;

typedef struct {
    char msg[STR_SIZE];
    int msg_size;
    HRESULT hr;
    char* protectedBlob;
    int protectedBlobSize;
    char log[LOG_SIZE];
}MessageDataInfo;

typedef struct {
    HRESULT hr;
    char* protectedBlob;
    int protectedBlobSize;
}ProtectedBolbInfo;