#pragma once

#define GAME_WIND_CLASS_NAME _T("TianLongBaBu WndClass")

#define MAX_GAME_COUNT 10

typedef struct {
    DWORD hp;
    DWORD mp;
} Charactar;

typedef struct {
	HWND m_list[MAX_GAME_COUNT];
	DWORD m_length;
} GameHWndList;

class CGameManager
{
private:
    HWND	m_hWnd;
    DWORD	m_pid;
    HANDLE	m_hProc;
    TCHAR	m_szWndText[MAX_PATH];

public:
    CGameManager(HWND hWnd);
    ~CGameManager();

	DWORD	GetProcessId() const;
	TCHAR*	GetWindowText() const;
	HWND	GetHwnd() const;
	HANDLE	OpenProcess();
	BOOL	CloseProcess();
	HMODULE LoadLibrary(TCHAR* szDllPath);
	BOOL	UnLoadLibrary(TCHAR* szDllPath);

	static	VOID Trace(TCHAR* pszFormat, ...);
    static	DWORD CGameManager::FindGames(CGameManager** games, DWORD maxCount);
};

