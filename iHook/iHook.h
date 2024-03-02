#pragma once

#include "Windows.h"

#define IHOOK_ASSERT assert
#define MAX_BACKUP_CODE_SIZE 0x10

typedef enum {
	IHOOK_TYPE_INLINE = 0,
	IHOOK_TYPE_WIN32_API = 1
} IHOOK_TYPE;

#define IHOOK_TYPE_DEFAULT IHOOK_TYPE_INLINE

typedef struct {
	DWORD edi;
	DWORD esi;
	DWORD ebp;
	DWORD esp;
	DWORD ebx;
	DWORD edx;
	DWORD ecx;
	DWORD eax;
} IHOOK_REGISTERS;

typedef struct {
	IHOOK_REGISTERS regs;
	IHOOK_TYPE      type;
	HANDLE          hProcess;
	LPVOID          lpHookAddress;
	LPVOID          lpDelegateAddress;
	LPVOID          lpCallbackAddress;
	LPVOID          lpCallbackParam;
	BYTE            byteBackupCode[MAX_BACKUP_CODE_SIZE];
	DWORD           dwBackupCodeSize;
	TCHAR           szModuleName[MAX_PATH];
	TCHAR           szAPIName[MAX_PATH];
} IHOOK_STATE;

typedef void (__stdcall *IHOOK_CALLBACK)(IHOOK_STATE*, LPCVOID lpCallbackParam);

BOOL IHookInitState(IHOOK_STATE* pHookState);
VOID IHookSetType(IHOOK_STATE* pHookState, IHOOK_TYPE type);

VOID IHookTrace(const TCHAR* pszFormat, ...);

// --- for default hook
VOID IHookSetAddress(IHOOK_STATE* pHookState, LPVOID lpHookAddress);
VOID IHookSetCallback(IHOOK_STATE* pHookState, LPVOID lpHookCallback);
VOID IHookSetCallbackParam(IHOOK_STATE* pHookState, LPVOID lpCallbackParam);

// for api hook
VOID IHookSetModuleName(IHOOK_STATE* pHookState, PTCHAR pszModName);
VOID IHookSetAPIName(IHOOK_STATE* pHookState, PTCHAR pszProcName);
LPVOID IHookGetAPIDelegate(IHOOK_STATE* pHookState);

// common
BOOL IHookSetHook(IHOOK_STATE* pHookState);
BOOL IHookUnsetHook(IHOOK_STATE* pHookState);

// for default hook
DWORD IHookReadEax(IHOOK_STATE* pHookState);
DWORD IHookReadEbx(IHOOK_STATE* pHookState);
DWORD IHookReadEcx(IHOOK_STATE* pHookState);
DWORD IHookReadEdx(IHOOK_STATE* pHookState);
DWORD IHookReadEsp(IHOOK_STATE* pHookState);
DWORD IHookReadEbp(IHOOK_STATE* pHookState);
DWORD IHookReadEsi(IHOOK_STATE* pHookState);
DWORD IHookReadEdi(IHOOK_STATE* pHookState);

DWORD IHookReadEaxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEbxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEcxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEdxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEspAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEbpAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEsiAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);
DWORD IHookReadEdiAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize);

