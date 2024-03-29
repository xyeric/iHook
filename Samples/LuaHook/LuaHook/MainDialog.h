#pragma once
#include "afxcmn.h"
#include "LuaHook.h"
#include "../../../iHook/iHook.h"

#define MAIN_WINDOW_WIDTH  600
#define MAIN_WINDOW_HEIGHT 400

#define GAME_WIND_CLASS_NAME _T("TianLongBaBu WndClass")

#define DEFAULT_LUA_STATE_FEATURE "E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 7D ?? ?? 8B 01 8D 75 D4 0F 43 75 D4 FF 50 3C 56 FF 30 FF 15 ?? ?? ?? ?? 83 C4 08"
#define DEFAULT_LUA_STATE_FEATURE_OFFSET 0x07

const UINT WM_UPDATEDATA = ::RegisterWindowMessage("WM_UPDATEDATA");
const DWORD IHOOK_MESSAGE_LUA_DO_STRING = ::RegisterWindowMessage("IHOOK_MESSAGE_LUA_DO_STRING");

// MainDialog 对话框

class MainDialog : public CDialog
{
	DECLARE_DYNAMIC(MainDialog)

public:
	MainDialog();
	virtual ~MainDialog();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MAIN_WINDOW };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	DECLARE_MESSAGE_MAP()
public:
    virtual BOOL OnInitDialog();

	HWND GetGameHWnd();
	HHOOK SetGameWindowHook();
	BOOL UnSetGameWindowHook();

private:

public:
	IHOOK_STATE m_hookState;
	BOOL		m_bLuaHookEnabled;
	CString		m_szLuaHookStatus;
	HHOOK		m_hWindowHook;
	CString		m_szHookAddress;
	CString		m_szLuaChunck;
	BOOL		m_bFilterLuaStringEanble;
	CString		m_szFilterString;
	CString		m_szTestLuaString;

	afx_msg void OnBnClickedButtonSetHook();
	afx_msg void OnBnClickedButtonStopHook();
	afx_msg void OnBnClickedButtonAddFilterString();
	afx_msg void OnBnClickedButtonTestLuaString();
	afx_msg void OnBnClickedButtonSaveFilterString();
	afx_msg void OnBnClickedCheckFilterLuaString();
	afx_msg LRESULT OnUpdateData(WPARAM wParam, LPARAM lParam);
	virtual void OnCancel();
};
