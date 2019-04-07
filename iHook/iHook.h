#pragma once

#include "Windows.h"

#define MAX_BACKUP_CODE_SIZE 0x10

typedef struct {
	DWORD edi;
	DWORD esi;
	DWORD ebp;
	DWORD esp;
	DWORD ebx;
	DWORD edx;
	DWORD ecx;
	DWORD eax;
} IHookRegisters;

typedef struct {
	IHookRegisters regs;
	HANDLE         hProcess;
	LPVOID         lpHookAddress;
	LPVOID         lpDelegateAddress;
	LPVOID         lpCallbackAddress;
	LPVOID         lpCallbackParam;
	BYTE           byteBackupCode[MAX_BACKUP_CODE_SIZE];
	DWORD          dwBackupCodeSize;
} IHookState;

typedef void (__stdcall *IHookCallback)(IHookState*, LPVOID lpCallbackParam);

BOOL IHookInitState(IHookState* pHookState);
BOOL IHookStartHook(IHookState* pHookState);
BOOL IHookStopHook(IHookState* pHookState);
VOID IHookSetHookAddress(IHookState* pHookState, LPVOID lpHookAddress);
VOID IHookSetCallback(IHookState* pHookState, IHookCallback lpHookCallback);
VOID IHookSetCallbackParam(IHookState* pHookState, LPVOID lpCallbackParam);

DWORD IHookReadEax(IHookState* pHookState);
DWORD IHookReadEbx(IHookState* pHookState);
DWORD IHookReadEcx(IHookState* pHookState);
DWORD IHookReadEdx(IHookState* pHookState);
DWORD IHookReadEsp(IHookState* pHookState);
DWORD IHookReadEbp(IHookState* pHookState);
DWORD IHookReadEsi(IHookState* pHookState);
DWORD IHookReadEdi(IHookState* pHookState);

DWORD IHookReadEaxAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEbxAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEcxAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEdxAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEspAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEbpAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEsiAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEdiAsString(IHookState* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);

VOID IHookTrace(const TCHAR* pszFormat, ...);
