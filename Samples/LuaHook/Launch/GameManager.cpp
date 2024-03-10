#include "stdafx.h"
#include "GameManager.h"

CGameManager::CGameManager(HWND hWnd)
{
	m_hWnd = hWnd;

    ::GetWindowText(hWnd, m_szWndText, sizeof(m_szWndText));

    ::GetWindowThreadProcessId(m_hWnd, &m_pid);
}


CGameManager::~CGameManager()
{
}


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	GameHWndList* pGameHWndList = (GameHWndList*)lParam;
	if (GetParent(hWnd) == NULL && IsWindowVisible(hWnd) && pGameHWndList->m_length < MAX_GAME_COUNT) {
		TCHAR szClassName[MAX_PATH];
		::GetClassName(hWnd, szClassName, MAX_PATH);

		if (_tcscmp(szClassName, GAME_WIND_CLASS_NAME) == 0) {
			pGameHWndList->m_list[pGameHWndList->m_length++] = hWnd;
		}
	}

	return TRUE;
}

DWORD CGameManager::FindGames(CGameManager** pGameManagers, DWORD maxCount) {
	GameHWndList gameHWndList = { 0 };
	::EnumWindows(EnumWindowsProc, (LPARAM)&gameHWndList);

	DWORD gameCount = gameHWndList.m_length;
	for (DWORD i = 0; i < gameCount; i++) {
		pGameManagers[i] = new CGameManager(gameHWndList.m_list[i]);
	}

	return gameCount;
}

DWORD CGameManager::GetProcessId() const
{
	return m_pid;
}

TCHAR* CGameManager::GetWindowText() const
{
	return (TCHAR*)m_szWndText;
}

HWND CGameManager::GetHwnd() const
{
	return m_hWnd;
}

HANDLE CGameManager::OpenProcess()
{
	if (m_hProc == NULL) {
		m_hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
	}

	return m_hProc;
}

BOOL CGameManager::CloseProcess()
{
	if (m_hProc != NULL) {
		::CloseHandle(m_hProc);
		m_hProc = NULL;
	}

	return TRUE;
}


HMODULE CGameManager::LoadLibrary(TCHAR* szDllPath)
{
	HANDLE hProc = m_hProc;
	if (hProc == NULL) {
		hProc = this->OpenProcess();
	}

	if (hProc == NULL) {
		CGameManager::Trace(_T("cannot open game process"));
		this->CloseProcess();
		return FALSE;
	}

	DWORD dwBufSize = (_tcslen(szDllPath) + 1) * sizeof(TCHAR);

	LPVOID lpAddr = ::VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr == NULL) {
		CGameManager::Trace(_T("cannot alloc remote memery for dll path"));
		this->CloseProcess();
		return NULL;
	}

	SIZE_T lwriteSize;
	BOOL ret = ::WriteProcessMemory(hProc, lpAddr, szDllPath, dwBufSize, &lwriteSize);
	if (!ret || lwriteSize != dwBufSize) {
		CGameManager::Trace(_T("write dll path into remote memery failed"));
		this->CloseProcess();
		return NULL;
	}

	LPTHREAD_START_ROUTINE pFunc = (LPTHREAD_START_ROUTINE)::LoadLibrary;
	HANDLE hThrd = ::CreateRemoteThread(hProc, NULL, 0, pFunc, lpAddr, 0, NULL);

	::WaitForSingleObject(hThrd, INFINITE);

	HMODULE hDll;
	::GetExitCodeThread(hThrd, (LPDWORD)&hDll);
	if (hDll == NULL) {
		CGameManager::Trace(_T("cannot get dll module handle"));
	}

	ret = ::VirtualFreeEx(hProc, lpAddr, dwBufSize, MEM_DECOMMIT);
	if (!ret) {
		CGameManager::Trace(_T("cannot free remote memery"));
	}

	::CloseHandle(hThrd);
	this->CloseProcess();

	return hDll;
}

BOOL CGameManager::UnLoadLibrary(TCHAR* szDllPath)
{
	HANDLE hProc = m_hProc;
	if (hProc == NULL) {
		hProc = this->OpenProcess();
	}

	if (hProc == NULL) {
		CGameManager::Trace(_T("cannot open game process"));
		this->CloseProcess();
		return FALSE;
	}

	DWORD dwBufSize = (_tcslen(szDllPath) + 1) * sizeof(TCHAR);

	LPVOID lpAddr = ::VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr == NULL) {
		CGameManager::Trace(_T("cannot alloc remote memery for dll path"));
		this->CloseProcess();
		return FALSE;
	}

	SIZE_T lwriteSize;
	BOOL ret = ::WriteProcessMemory(hProc, lpAddr, szDllPath, dwBufSize, &lwriteSize);
	if (!ret || lwriteSize != dwBufSize) {
		CGameManager::Trace(_T("write dll path into remote memery failed"));
		this->CloseProcess();
		return FALSE;
	}

	LPTHREAD_START_ROUTINE pFunc = (LPTHREAD_START_ROUTINE)::GetModuleHandle;
	HANDLE hThrd = ::CreateRemoteThread(hProc, NULL, 0, pFunc, lpAddr, 0, NULL);

	::WaitForSingleObject(hThrd, INFINITE);

	HMODULE hDll;
	::GetExitCodeThread(hThrd, (LPDWORD)&hDll);
	if (hDll == NULL) {
		CGameManager::Trace(_T("cannot get dll module handle"));
		this->CloseProcess();
		return FALSE;
	}

	ret = ::VirtualFreeEx(hProc, lpAddr, dwBufSize, MEM_DECOMMIT);
	if (!ret) {
		CGameManager::Trace(_T("cannot free remote memery"));
	}

	::CloseHandle(hThrd);

	pFunc = (LPTHREAD_START_ROUTINE)::FreeLibrary;
	hThrd = ::CreateRemoteThread(hProc, NULL, 0, pFunc, hDll, 0, NULL);

	::WaitForSingleObject(hThrd, INFINITE);
	::CloseHandle(hThrd);
	this->CloseProcess();

	return TRUE;
}

VOID CGameManager::Trace(TCHAR* pszFormat, ...)
{
	TCHAR szMsg[MAX_PATH];
	va_list argList;
	va_start(argList, pszFormat);

	_vstprintf_s(szMsg, pszFormat, argList);

	TCHAR szMsgWithPrefix[MAX_PATH];
	_stprintf_s(szMsgWithPrefix, _T("[Launch] %s"), szMsg);

	::OutputDebugString(szMsgWithPrefix);

	va_end(argList);

}
