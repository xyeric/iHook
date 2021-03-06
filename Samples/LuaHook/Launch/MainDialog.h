
// MainDialog.h: 头文件

#include "Game.h"

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
	Game* m_games[MAX_GAMES_QUEUE];
	TCHAR m_szGameDllPath[MAX_PATH];

	// 游戏列表视图
	CListCtrl m_listGames;

	void RefreshGameList();
	Game* GetSelectedGame();
	afx_msg void OnBnClickedBtnRun();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnUnloadLibrary();
	afx_msg void OnBnClickedBtnRefresh();
	afx_msg void OnHdnItemclickList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnItemActivateList(NMHDR *pNMHDR, LRESULT *pResult);
private:
	// 游戏列表状态描述
	CString m_szGameLisState;
};
