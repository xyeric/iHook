// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "tchar.h"
#include "iostream"
#include "Memory.h"
#include "../../iHook/iHook.h"

#pragma comment(lib, "../../Debug/iHook.lib")

VOID RecursiveCreateDirectories(TCHAR* szDir)
{
	TCHAR szDirCopy[MAX_PATH];
	memcpy(szDirCopy, szDir, MAX_PATH);

	if (strlen(szDirCopy) <= 3) return;

	if (szDirCopy[strlen(szDirCopy) - 1] == '\\') {
		szDirCopy[strlen(szDirCopy) - 1] = _T('\0');
	}

	WIN32_FIND_DATA wfd;
	HANDLE hFind = ::FindFirstFile(szDirCopy, &wfd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		FindClose(hFind);
		if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return;
	}

	if (CreateDirectory(szDirCopy, NULL) == FALSE) {
		TCHAR* szNewDir = szDirCopy;
		while (szNewDir[strlen(szNewDir) - 1] != '\\') {
			szNewDir[strlen(szNewDir) - 1] = _T('\0');
		}

		szNewDir[strlen(szNewDir) - 1] = _T('\0');

		RecursiveCreateDirectories(szNewDir);

		CreateDirectory(szNewDir, NULL);
	}
}

void __stdcall LuaHookCallback(IHOOK_STATE* pHookState, LPVOID lpCallbackParam)
{
	try {
		// to read which register and read as which type, depends on situation
		BYTE* dwStackTop = (BYTE*)pHookState->regs.ebp;
		const TCHAR** pszFileName = (const TCHAR**)(dwStackTop + 0x14);
		const TCHAR** pszFileContent = (const TCHAR**)(dwStackTop + 0xC);
		if (pszFileName == NULL || pszFileContent == NULL) {
			IHookTrace(_T("lua script ignored. invalid filename or file content hooked"));
			return;
		}

		const TCHAR* szFileName = *pszFileName;
		const TCHAR* szFileContent = *pszFileContent;
		if (strcmp(&szFileName[strlen(szFileName) - 4], _T(".lua")) != 0) {
			IHookTrace(_T("lua script ignored. filename is not end with .lua %s"), szFileName);
			return;
		}

		TCHAR szFullPath[MAX_PATH];
		memcpy(szFullPath, lpCallbackParam, MAX_PATH);
		strcat_s(szFullPath, szFileName);

		TCHAR* pFind = szFullPath;
		while (*pFind != '\0') {
			if (*pFind == '/') *pFind = '\\';
			pFind++;
		}

		RecursiveCreateDirectories(szFullPath);

		FILE* fp;
		fopen_s(&fp, szFullPath, _T("w"));
		if (fp == NULL) {
			IHookTrace(_T("open lua script file failed. %s"), szFullPath);
			return;
		}

		fprintf(fp, "%s", szFileContent);
		fclose(fp);

		IHookTrace(_T("lua script has saved. %s"), szFullPath);
	}
	catch (...) {
		IHookTrace(_T("lua script extract error: 0x%x"), (DWORD)pHookState->regs.ebp);
	}
}

TCHAR szScriptDirectory[MAX_PATH];
BOOL SetLuaScriptHook(IHOOK_STATE* pHookState)
{
	HMODULE hModule = ::GetModuleHandle(_T("luaplus.dll"));

	if (hModule == NULL) return FALSE;

	DWORD lua_dobuffer = (DWORD)::GetProcAddress(hModule, _T("lua_dobuffer"));
	DWORD dwHookAddress = lua_dobuffer + 1;

	if (dwHookAddress == NULL) return FALSE;

	// ::CloseHandle(hModule);

	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)SetLuaScriptHook, &hModule);
	if (hModule == NULL) {
		IHookTrace(_T("set lua script hook error. cannot get current dll module handle."));
		return FALSE;
	}

	//TCHAR szScriptDirectory[MAX_PATH];
	DWORD dwIniPathLength = ::GetModuleFileName(hModule, szScriptDirectory, MAX_PATH);

	if (::FreeLibrary(hModule) == FALSE) {
		IHookTrace(_T("set lua script hook error. get work directory failed, cannot free module handle"));
		return FALSE;
	}

	TCHAR* pFind = _tcsrchr(szScriptDirectory, '\\');
	if (pFind == NULL) {
		IHookTrace(_T("set lua script hook error. get work directory failed"));
		return FALSE;
	}

	*pFind = '\0';

	strcat_s(szScriptDirectory, _T("\\Lua Scripts\\"));
	RecursiveCreateDirectories(szScriptDirectory);

	IHookTrace(_T("Hook address: 0x%x %s"), dwHookAddress, szScriptDirectory);

	IHookSetType(pHookState, IHOOK_TYPE_DEFAULT);
	IHookSetAddress(pHookState, LPVOID(dwHookAddress));
	IHookSetCallback(pHookState, LPVOID(LuaHookCallback));
	IHookSetCallbackParam(pHookState, (LPVOID)szScriptDirectory);

	IHookSetHook(pHookState);

	return TRUE;
}

void UnSetLuaScriptHook(IHOOK_STATE* pHookState)
{
	IHookUnsetHook(pHookState);
}

IHOOK_STATE g_hookState;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

		IHookTrace(_T("lua script hook dll thread attached"));
		IHookInitState(&g_hookState);

		IHookTrace(_T("start lua script hook"));
		SetLuaScriptHook(&g_hookState);
		break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		IHookTrace(_T("stop lua script hook"));
		UnSetLuaScriptHook(&g_hookState);
        break;
    }
    return TRUE;
}

