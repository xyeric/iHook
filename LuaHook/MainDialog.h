#pragma once
#include "afxcmn.h"
#include "LuaHook.h"
#include "../Hook/hook.h"

#define MAIN_WINDOW_WIDTH 600
#define MAIN_WINDOW_HEIGHT 400

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
private:

public:
	IHookState m_hookState;
	CString m_szHookAddress;
	CString m_szLuaString;
	BOOL m_bFilterLuaStringEanble;
	CString m_szFilterString;
	CString m_szTestLuaString;
	afx_msg void OnBnClickedButtonSetHook();
	afx_msg void OnBnClickedButtonStopHook();
	afx_msg void OnBnClickedButtonAddFilterString();
	afx_msg void OnBnClickedButtonTestLuaString();
	afx_msg void OnBnClickedButtonSaveFilterString();
	afx_msg void OnBnClickedCheckFilterLuaString();
};
