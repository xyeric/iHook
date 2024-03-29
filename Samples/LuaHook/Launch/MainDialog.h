
// MainDialog.h: 头文件

#include "GameManager.h"

#pragma once

// CMainDialog 对话框
class CMainDialog : public CDialog
{
// 构造
public:
	CMainDialog(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LAUNCH_MAIN_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

	DWORD m_gameCount = 0;
	CGameManager* m_pGameManagers[MAX_GAME_COUNT];
	TCHAR m_szGameDllPath[MAX_PATH];

	// 游戏列表视图
	CListCtrl m_listGames;

	void RefreshGameList();
	CGameManager* GetSelectedGame();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedLoadLuaHookDll();
	afx_msg void OnBnClickedUnloadLuaHookDll();
	afx_msg void OnBnClickedUnloadLuaScriptHookDll();
	afx_msg void OnBnClickedBtnLoadLuaScriptHookDll();
	afx_msg void OnBnClickedBtnRefresh();
	afx_msg void OnHdnItemclickList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemActivateList(NMHDR *pNMHDR, LRESULT *pResult);
private:
	// 游戏列表状态描述
	CString m_szGameLisState;
public:
};
