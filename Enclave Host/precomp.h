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

//Enclave Host header file

#pragma once

#define STR_SIZE 1024
#define BUFFER_SIZE 32'768

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <string>

typedef struct {
    HRESULT hr;
    BYTE Report[BUFFER_SIZE];
    UINT32 ReportSize;
}ReportDataInfo;

typedef struct {
    char msg[STR_SIZE];
    int msg_size;
    HRESULT hr;
    PVOID protectedBlob;
    int protectedBolbSize;
}MessageDataInfo;

typedef struct {
    HRESULT hr;
    PVOID protectedBlob;
    int protectedBolbSize;
}ProtectedBolbInfo;