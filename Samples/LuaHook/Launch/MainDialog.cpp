
// MainDialog.cpp: 实现文件
//

#include "stdafx.h"
#include "Launch.h"
#include "MainDialog.h"
#include "afxdialogex.h"
#include "Game.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMainDialog 对话框


CMainDialog::CMainDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_LAUNCH_MAIN_DIALOG, pParent)
	, m_szGameLisState(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST, m_listGames);
	DDX_Text(pDX, IDC_STATIC_LIST_STATE, m_szGameLisState);
}

BEGIN_MESSAGE_MAP(CMainDialog, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_BTN_RUN, &CMainDialog::OnBnClickedBtnRun)
	ON_BN_CLICKED(IDCANCEL, &CMainDialog::OnBnClickedCancel)
	ON_BN_CLICKED(ID_UNLOAD, &CMainDialog::OnBnUnloadLibrary)
	ON_BN_CLICKED(ID_BTN_REFRESH, &CMainDialog::OnBnClickedBtnRefresh)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &CMainDialog::OnHdnItemclickList)
	ON_NOTIFY(LVN_ITEMACTIVATE, IDC_LIST, &CMainDialog::OnLvnItemActivateList)
END_MESSAGE_MAP()


// CMainDialog 消息处理程序

BOOL CMainDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_listGames.InsertColumn(0, _T("进程ID"), LVCFMT_LEFT, 160, 1);
	m_listGames.InsertColumn(1, _T("窗口名称"), LVCFMT_LEFT, -1, -1);
	m_listGames.SetColumnWidth(1, LVSCW_AUTOSIZE_USEHEADER);

	m_listGames.SetExtendedStyle(
				LVS_EX_GRIDLINES |
				LVS_EX_ONECLICKACTIVATE |
				LVS_EX_CHECKBOXES |
				LVS_EX_AUTOCHECKSELECT |
				LVS_EX_FULLROWSELECT);

	
	RefreshGameList();

	// 获取需要注入的DLL路径
	DWORD dwCurDirPathLen = ::GetCurrentDirectory(MAX_PATH, m_szGameDllPath);
	if (dwCurDirPathLen > 0) {
		_tcscat_s(m_szGameDllPath, _T("\\LuaHook.dll"));
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMainDialog::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMainDialog::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMainDialog::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

VOID CMainDialog::RefreshGameList()
{
	m_szGameLisState = "未选择游戏进程！";

	// 获取游戏列表
	m_gameCount = Game::FindGames(m_games, MAX_GAMES_QUEUE);

	m_listGames.DeleteAllItems();
	for (DWORD i = 0; i < m_gameCount; i++) {
		CString szPid;
		DWORD dwTest = 111;
		szPid.Format(_T("%d"), m_games[i]->GetProcessId());

		m_listGames.InsertItem(0, szPid);
		m_listGames.SetItemText(0, 1, m_games[i]->GetWindowText());
	}

	if (m_gameCount > 0) {
		m_szGameLisState.Format(_T("找到 %d 个游戏窗口"), m_gameCount);
	}
	else {
		m_szGameLisState = "未找到游戏窗口";
	}

	UpdateData(false);
}

Game* CMainDialog::GetSelectedGame()
{
	UpdateData(TRUE);

	DWORD index = (DWORD)m_listGames.GetFirstSelectedItemPosition();

	if (index == NULL) return NULL;

	return m_games[index - 1];
}

void CMainDialog::OnBnClickedBtnRun()
{
	Game* pGame = GetSelectedGame();
 	if (pGame == NULL) {
		::MessageBox(NULL, _T("请请选择进程进行注入"), _T("错误提示"), MB_OK);
		return;
	}

	HMODULE hMod = pGame->LoadLibrary(m_szGameDllPath);
	if (hMod == NULL) {
		::MessageBox(NULL, _T("进程注入失败！"), _T("错误提示"), MB_OK);
	}
}

void CMainDialog::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialog::OnCancel();
}


void CMainDialog::OnBnUnloadLibrary()
{
	Game* pGame = GetSelectedGame();
	if (pGame == NULL) {
		::MessageBox(NULL, _T("请请选择进程进行卸载！"), _T("错误提示"), MB_OK);
		return;
	}

	BOOL ret = pGame->UnLoadLibrary(m_szGameDllPath);
	if (!ret) {
		::MessageBox(NULL, _T("卸载失败！"), _T("错误提示"), MB_OK);
		return;
	}

	::MessageBox(NULL, _T("卸载成功！"), _T("恭喜你"), MB_OK);
}

void CMainDialog::OnBnClickedBtnRefresh()
{
	RefreshGameList();
}


void CMainDialog::OnHdnItemclickList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMHEADER phdr = reinterpret_cast<LPNMHEADER>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CMainDialog::OnLvnItemActivateList(NMHDR *pNMHDR, LRESULT *pResult)
{
	Game* pGame = GetSelectedGame();
	if (pGame && _tcslen(pGame->GetWindowText()) > 0) {
		m_szGameLisState.Format(_T("当前选中游戏进程：%d"), pGame->GetProcessId());
		UpdateData(FALSE);
	}
}
          