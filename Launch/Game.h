#pragma once

#define GAME_WIND_CLASS_NAME _T("TianLongBaBu WndClass")

#define MAX_GAMES_QUEUE 10

typedef struct {
    DWORD hp;
    DWORD mp;
} Charactar;

typedef struct {
	HWND m_list[MAX_GAMES_QUEUE];
	DWORD m_length;
} GameHWndList;

class Game
{
private:
    HWND m_hWnd;
    DWORD m_pid;
    HANDLE m_hProc;
    TCHAR m_szWndText[MAX_PATH];
    LPCVOID m_charBaseAddr;

public:
    Game(HWND hWnd);
    ~Game();

	DWORD GetProcessId() const;
	TCHAR* GetWindowText() const;
	HWND GetHwnd() const;
	HANDLE OpenProcess();
	BOOL CloseProcess();
	HMODULE LoadLibrary(TCHAR* szDllPath);
	BOOL UnLoadLibrary(TCHAR* szDllPath);

	static VOID Trace(TCHAR* pszFormat, ...);
    static DWORD Game::FindGames(Game** games, DWORD maxCount);
};

