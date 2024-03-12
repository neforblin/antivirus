#pragma once
#ifndef header_h
#define header_h

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

TCHAR szCommand[10];
TCHAR szSvcName[80];

extern VOID __stdcall DisplayUsage(void);

#endif // !header.h
