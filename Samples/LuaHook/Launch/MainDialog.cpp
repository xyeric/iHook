
// MainDialog.cpp: 实现文件
//

#include "stdafx.h"
#include "Launch.h"
#include "MainDialog.h"
#include "afxdialogex.h"
#include "GameManager.h"

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
	, m_pGameManagers()
	, m_szGameDllPath(_T(""))
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
	ON_BN_CLICKED(IDCANCEL, &CMainDialog::OnBnClickedCancel)
	ON_BN_CLICKED(ID_BTN_REFRESH, &CMainDialog::OnBnClickedBtnRefresh)
	ON_NOTIFY(HDN_ITEMCLICK, 0, &CMainDialog::OnHdnItemclickList)
	ON_NOTIFY(LVN_ITEMACTIVATE, IDC_LIST, &CMainDialog::OnLvnItemActivateList)
	ON_BN_CLICKED(ID_BTN_LOAD_LUA_HOOK_DLL, &CMainDialog::OnBnClickedLoadLuaHookDll)
	ON_BN_CLICKED(ID_BTN_UNLOAD_LUA_HOOK_DLL, &CMainDialog::OnBnClickedUnloadLuaHookDll)
	ON_BN_CLICKED(ID_BTN_UNLOAD_LUA_SCRIPT_HOOK_DLL, &CMainDialog::OnBnClickedUnloadLuaScriptHookDll)
	ON_BN_CLICKED(ID_BTN_LOAD_LUA_SCRIPT_HOOK_DLL, &CMainDialog::OnBnClickedBtnLoadLuaScriptHookDll)
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

	for (size_t i = 0; i < m_gameCount; i++) {
		if (m_pGameManagers[i]) {
			delete m_pGameManagers[i];
			m_pGameManagers[i] = NULL;
		}
	}

	m_gameCount = 0;

	// 获取游戏列表
	m_gameCount = CGameManager::FindGames(m_pGameManagers, MAX_GAME_COUNT);

	m_listGames.UpdateData();

	for (DWORD i = 0; i < (DWORD)m_listGames.GetItemCount(); i++) {
		DWORD dwPid = m_listGames.GetItemData(i);;
		BOOL bProcFound = FALSE;

		for (DWORD j = 0; j < m_gameCount; j++) {
			if (dwPid == m_pGameManagers[j]->GetProcessId()) bProcFound = TRUE;
		}

		if (bProcFound == FALSE) {
			m_listGames.DeleteItem(i);
		}
	}

	for (DWORD i = 0; i < m_gameCount; i++) {
		DWORD dwPid = m_pGameManagers[i]->GetProcessId();
		BOOL bProcExist = FALSE;

		DWORD dwItemCount = (DWORD)m_listGames.GetItemCount();
		for (DWORD j = 0; j < dwItemCount; j++) {
			if (dwPid == m_listGames.GetItemData(j)) {
				m_listGames.SetItemText(j, 2, m_pGameManagers[i]->GetWindowText());
				bProcExist = TRUE;
			}
		}

		if (bProcExist == FALSE) {
			CString szPid;
			szPid.Format(_T("%d"), dwPid);

			m_listGames.InsertItem(dwItemCount, szPid);
			m_listGames.SetItemText(dwItemCount, 1, m_pGameManagers[i]->GetWindowText());
			m_listGames.SetItemData(dwItemCount, dwPid);
		}
	}

	m_listGames.UpdateWindow();

	DWORD dwSelectedItemPosition = (DWORD)m_listGames.GetFirstSelectedItemPosition();
	if (dwSelectedItemPosition == NULL) {
		m_szGameLisState.Format(_T("请选中游戏进程进行操作"));
		UpdateData(FALSE);
	}
}

CGameManager* CMainDialog::GetSelectedGame()
{
	m_listGames.UpdateData();

	DWORD dwSelectedItemPosition = (DWORD)m_listGames.GetFirstSelectedItemPosition();
	if (dwSelectedItemPosition != NULL) {
		DWORD dwPid = m_listGames.GetItemData(dwSelectedItemPosition - 1);
		for (DWORD i = 0; i < m_gameCount; i++) {
			if (dwPid == m_pGameManagers[i]->GetProcessId()) return m_pGameManagers[i];
		}
	}

	return NULL;
}

void CMainDialog::OnBnClickedLoadLuaHookDll()
{
	CGameManager* pGameManager = GetSelectedGame();
 	if (pGameManager == NULL) {
		::MessageBox(NULL, _T("请请选择进程进行注入"), _T("错误提示"), MB_OK);
		return;
	}

	HMODULE hMod = pGameManager->LoadLibrary(m_szGameDllPath);
	if (hMod == NULL) {
		::MessageBox(NULL, _T("进程注入失败！"), _T("错误提示"), MB_OK);
	}
}

void CMainDialog::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialog::OnCancel();
}

void CMainDialog::OnBnClickedUnloadLuaHookDll()
{
	CGameManager* pGameManager = GetSelectedGame();
	if (pGameManager == NULL) {
		::MessageBox(NULL, _T("请请选择进程进行卸载！"), _T("错误提示"), MB_OK);
		return;
	}

	BOOL ret = pGameManager->UnLoadLibrary(m_szGameDllPath);
	if (!ret) {
		::MessageBox(NULL, _T("卸载失败！"), _T("错误提示"), MB_OK);
		return;
	}

	::MessageBox(NULL, _T("卸载成功！"), _T("恭喜你"), MB_OK);
}

void CMainDialog::OnBnClickedBtnLoadLuaScriptHookDll()
{
	CString szGameBinPath = _T("E:\\Game\\TLBB\\XTLBB\\Bin");

	SHELLEXECUTEINFO info;
	memset(&info, 0, sizeof(info));

	info.cbSize = sizeof(SHELLEXECUTEINFO);
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.hwnd = NULL;
	info.lpVerb = _T("open");
	info.lpFile = _T("Game.exe");
	info.lpParameters = _T("-fl");
	info.lpDirectory = szGameBinPath;
	info.nShow = SW_SHOW;
	info.hInstApp = NULL;
	info.hProcess = NULL;

	::ShellExecuteEx(&info);

	if (info.hProcess == NULL) return;

	// HINSTANCE hInstance = ::ShellExecute(NULL, _T("open"), _T("CGameManager.exe"), _T("-fl"), szGameBinPath, SW_SHOW);

	//::WinExec("D:\\CGameManager\\XTLBB\\Bin\\CGameManager.exe -fl", SW_SHOW);

	DWORD dwProcId = GetProcessId(info.hProcess);

	Sleep(2000);

	TCHAR szDllPath[MAX_PATH];
	DWORD dwCurDirPathLen = ::GetCurrentDirectory(MAX_PATH, szDllPath);
	if (dwCurDirPathLen > 0) {
		_tcscat_s(szDllPath, _T("\\LuaScriptHook.dll"));
	}

	CGameManager::Trace(_T("dll path %s"), szDllPath);
	HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcId);

	if (hProc == NULL) {
		CGameManager::Trace(_T("cannot open game process"));
		::CloseHandle(hProc);
		return;
	}

	DWORD dwBufSize = (_tcslen(szDllPath) + 1) * sizeof(TCHAR);

	LPVOID lpAddr = ::VirtualAllocEx(hProc, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr == NULL) {
		CGameManager::Trace(_T("cannot alloc remote memery for dll path"));
		::CloseHandle(hProc);
		return;
	}

	SIZE_T lwriteSize;
	BOOL ret = ::WriteProcessMemory(hProc, lpAddr, szDllPath, dwBufSize, &lwriteSize);
	if (!ret || lwriteSize != dwBufSize) {
		CGameManager::Trace(_T("write dll path into remote memery failed"));
		::CloseHandle(hProc);
		return;
	}

	LPTHREAD_START_ROUTINE pFunc = (LPTHREAD_START_ROUTINE)::LoadLibrary;
	HANDLE hThrd = ::CreateRemoteThread(hProc, NULL, 0, pFunc, lpAddr, 0, NULL);

	::WaitForSingleObject(hThrd, INFINITE);

	HMODULE hDll;
	::GetExitCodeThread(hThrd, (LPDWORD)&hDll);
	if (hDll == NULL) {
		CGameManager::Trace(_T("cannot get dll module handle"));
	}

	ret = ::VirtualFreeEx(hProc, lpAddr, 0, MEM_RELEASE);
	if (!ret) {
		CGameManager::Trace(_T("cannot free remote memery"));
	}

	CGameManager::Trace(_T("load lua script success"));

	::CloseHandle(hThrd);
	::CloseHandle(hProc);
	return;
}

void CMainDialog::OnBnClickedUnloadLuaScriptHookDll()
{
	TCHAR szDllPath[MAX_PATH];
	DWORD dwCurDirPathLen = ::GetCurrentDirectory(MAX_PATH, szDllPath);
	if (dwCurDirPathLen > 0) {
		_tcscat_s(m_szGameDllPath, _T("\\LuaScriptHook.dll"));
	}

	CGameManager* pGameManager = GetSelectedGame();
	if (pGameManager == NULL) {
		::MessageBox(NULL, _T("请请选择进程进行卸载！"), _T("错误提示"), MB_OK);
		return;
	}

	BOOL ret = pGameManager->UnLoadLibrary(szDllPath);
	if (!ret) {
		::MessageBox(NULL, _T("卸载失败！"), _T("错误提示"), MB_OK);
		return;
	}

	::MessageBox(NULL, _T("卸载成功！"), _T("恭喜你"), MB_OK);
}

void CMainDialog::OnLvnItemActivateList(NMHDR* pNMHDR, LRESULT* pResult)
{
	CGameManager* pGameManager = GetSelectedGame();
	if (pGameManager && _tcslen(pGameManager->GetWindowText()) > 0) {
		m_szGameLisState.Format(_T("当前选中游戏进程：%d"), pGameManager->GetProcessId());
		UpdateData(FALSE);
	}
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

