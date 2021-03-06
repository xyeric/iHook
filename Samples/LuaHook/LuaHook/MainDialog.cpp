// MainDialog.cpp : 实现文件
//

#include "stdafx.h"
#include "MainDialog.h"
#include "afxdialogex.h"

// MainDialog 对话框

#pragma comment(lib,"iHook.lib")

IMPLEMENT_DYNAMIC(MainDialog, CDialog)

MainDialog::MainDialog()
	: CDialog(IDD_MAIN_WINDOW, NULL)
	, m_szHookAddress(_T(""))
	, m_szLuaString(_T(""))
	, m_bFilterLuaStringEanble(TRUE)
	, m_hWindowHook(NULL)
	, m_szFilterString(_T(""))
	, m_szTestLuaString(_T("setmetatable(_G, { __index = MainMenuBar_Env});\r\nMainMenuBar_Clicked(1);"))
{
}

MainDialog::~MainDialog()
{
}

void MainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_HOOK_ADDRESS, m_szHookAddress);
	DDX_Text(pDX, IDC_EDIT_LUA_STRING, m_szLuaString);
	DDX_Check(pDX, IDC_CHECK_FILTER_LUA_STRING, m_bFilterLuaStringEanble);
	DDX_Text(pDX, IDC_EDIT_FILTER_STRING, m_szFilterString);
	DDX_Text(pDX, IDC_EDIT_TEST_LUA_STRING, m_szTestLuaString);
}

BEGIN_MESSAGE_MAP(MainDialog, CDialog)
	ON_REGISTERED_MESSAGE(WM_UPDATEDATA, OnUpdateData)
	ON_BN_CLICKED(IDC_BUTTON_SET_HOOK, &MainDialog::OnBnClickedButtonSetHook)
	ON_BN_CLICKED(IDC_BUTTON_STOP_HOOK, &MainDialog::OnBnClickedButtonStopHook)
	ON_BN_CLICKED(IDC_BUTTON_ADD_FILTER_STRING, &MainDialog::OnBnClickedButtonAddFilterString)
	ON_BN_CLICKED(IDC_BUTTON_TEST_LUA_STRING, &MainDialog::OnBnClickedButtonTestLuaString)
	ON_BN_CLICKED(IDC_BUTTON_SAVE_FILTER_STRING, &MainDialog::OnBnClickedButtonSaveFilterString)
	ON_BN_CLICKED(IDC_CHECK_FILTER_LUA_STRING, &MainDialog::OnBnClickedCheckFilterLuaString)
END_MESSAGE_MAP()

// MainDialog 消息处理程序
BOOL MainDialog::OnInitDialog()
{

    CDialog::OnInitDialog();

	IHookInitState(&m_hookState);

	SetGameWindowHook();

    return TRUE;  // return TRUE unless you set the focus to a control
}

DWORD StrToHex(TCHAR* pszStr)
{
	DWORD dwRet = 0;

	size_t start = 0, len = _tcslen(pszStr);
	if (pszStr[0] == '0' && (pszStr[1] == 'x' || pszStr[1] == 'X')) {
		start = 2;
	}
	for (size_t i = start; i < len; i++) {
		dwRet = dwRet * 16;
		if (pszStr[i] >= '0' && pszStr[i] <= '9') {
			dwRet += pszStr[i] - '0';
		}
		else if (pszStr[i] >= 'a' && pszStr[i] <= 'f') {
			dwRet += pszStr[i] - 'a' + 10;
		}
		else if (pszStr[i] >= 'A' && pszStr[i] <= 'F') {
			dwRet += pszStr[i] - 'A' + 10;
		}
	}

	return dwRet;
}

void __stdcall LuaHookCallback(IHOOK_STATE* pHookState, LPVOID lpCallbackParam)
{
	MainDialog* dlg = (MainDialog*)lpCallbackParam;

	// IHookTrace(_T("Hook callback: eax: 0x%x, ebx: 0x%x, ecx: 0x%x"), (LPVOID)pHookState->regs.eax, (LPVOID)pHookState->regs.ebx, (LPVOID)pHookState->regs.ecx);

	// canot call UpdateData cross threads
	dlg->SendMessage(WM_UPDATEDATA, TRUE);

	CString szLuaStr = "";
	try {
		// to read which register and read as which type, depends on situation
		szLuaStr.Format(_T("setmetatable(_G, { __index = %s});\r\n%s\r\n"), (TCHAR*)pHookState->regs.eax, (TCHAR*)pHookState->regs.ebx);
	}
	catch (...) {
		IHookTrace(_T("Eax: 0x%x"), (DWORD)pHookState->regs.eax);
	}

	if (szLuaStr.GetLength() == 0 ||
		dlg->m_szLuaString.Find(szLuaStr) >= 0 ||
		(dlg->m_bFilterLuaStringEanble && dlg->m_szFilterString.Find(szLuaStr) >= 0)) {
		return;
	}

	dlg->m_szLuaString += szLuaStr;

	dlg->SendMessage(WM_UPDATEDATA, FALSE);
}

typedef HWND (WINAPI *IHOOK_API_CALLBACK_NEXT)();

HWND WINAPI FakeGetForegroundWindow()
{
	//return 0x1212da; // fake caller for special purpose

	IHOOK_API_CALLBACK_NEXT GetForegroundWindow = (IHOOK_API_CALLBACK_NEXT)IHookGetAPIDelegate(NULL);
	HWND ret = GetForegroundWindow();

	IHookTrace(_T("call original api: 0x%x"), ret);

	return ret;
}

void MainDialog::OnBnClickedButtonSetHook()
{
	UpdateData(TRUE);

	DWORD dwHookAddress = StrToHex(m_szHookAddress.GetBuffer(0));
	m_szHookAddress.ReleaseBuffer();

	IHookTrace(_T("Hook address: 0x%x"), dwHookAddress);

	if (!dwHookAddress) {
		MessageBox(_T("请输入Hook地址"), _T("错误提示"), MB_OK);
		return;
	}

	//IHookSetAddress(&m_hookState, LPVOID(dwHookAddress));
	//IHookSetCallback(&m_hookState, LPVOID(LuaHookCallback));
	//IHookSetCallbackParam(&m_hookState, LPVOID(this));

	//IHookSetHook(&m_hookState);

	IHookSetType(&m_hookState, IHOOK_TYPE_WIN32_API);
	IHookSetModuleName(&m_hookState, _T("user32.dll"));
	IHookSetAPIName(&m_hookState, _T("GetForegroundWindow"));
	IHookSetCallback(&m_hookState, FakeGetForegroundWindow);

	IHookSetHook(&m_hookState);
}

void MainDialog::OnBnClickedButtonStopHook()
{
	IHookUnsetHook(&m_hookState);
}

void MainDialog::OnBnClickedButtonAddFilterString()
{
	m_szFilterString += m_szLuaString;
	m_szLuaString = "";

	UpdateData(FALSE);
}

void MainDialog::OnBnClickedButtonTestLuaString()
{
	UpdateData(TRUE);
	if (m_szTestLuaString.GetLength() > 0) {
		::SendMessage(GetGameHWnd(), IHOOK_MESSAGE_LUA_DO_STRING, NULL, (LPARAM)m_szTestLuaString.GetBuffer(0));
		m_szTestLuaString.ReleaseBuffer();
	}	
}

void MainDialog::OnBnClickedButtonSaveFilterString()
{
	CString szFileName = "";
	::GetCurrentDirectory(MAX_PATH, szFileName.GetBuffer(MAX_PATH));
	szFileName.ReleaseBuffer();
	szFileName += _T("LuaFilterString.txt");

	IHookTrace(_T("filter string saved at: %s"), szFileName.GetBuffer(0));
	szFileName.ReleaseBuffer();

	CFile file(szFileName, CFile::modeWrite | CFile::modeNoTruncate);

	file.Write(m_szFilterString, m_szFilterString.GetLength());

	file.Close();
}


void MainDialog::OnBnClickedCheckFilterLuaString()
{
	UpdateData(TRUE);
}

LRESULT MainDialog::OnUpdateData(WPARAM wParam, LPARAM lParam)
{
	UpdateData(wParam);

	return 0;
}

HRESULT CALLBACK IHookWindowHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode != HC_ACTION) {
		return ::CallNextHookEx(NULL, nCode, wParam, lParam);
	}

	/** eg:
	 * setmetatable(_G, { __index = ActionSkill_Env });
	 * SceneMap_GotoDirectly();
	 */

	CWPSTRUCT *lpArg = (CWPSTRUCT*)lParam;
	if (lpArg->message == IHOOK_MESSAGE_LUA_DO_STRING) {
		IHookTrace(_T("window hook get message: %s"), lpArg->lParam);

		TCHAR* pszLuaStr = (TCHAR*)lpArg->lParam;
		_asm {
			pushad
			mov ecx, dword ptr ds : [0x172B910]
			mov eax, dword ptr ds : [ecx]
			call dword ptr ds : [eax + 0x3C]
			push pszLuaStr
			push dword ptr ds : [eax]
			call dword ptr ds : [0x012B52B8]
			add esp, 8
			popad
		}

		IHookTrace(_T("call lua_dostring success"));
	}

	return ::CallNextHookEx(NULL, nCode, wParam, lParam);
}


HWND MainDialog::GetGameHWnd()
{
	HANDLE hProcess = ::GetCurrentProcess();
	DWORD dwProcessID = ::GetProcessId(hProcess);

	HWND hIterWnd = NULL, hRetWnd = NULL;
	do {
		hIterWnd = ::FindWindowEx(NULL, hIterWnd, NULL, NULL);
		DWORD dwPID = 0;
		GetWindowThreadProcessId(hIterWnd, &dwPID);

		TCHAR szClassName[MAX_PATH];
		::GetClassName(hIterWnd, szClassName, MAX_PATH);
		if (dwPID == dwProcessID && _tcscmp(GAME_WIND_CLASS_NAME, szClassName) == 0) {
			hRetWnd = hIterWnd;
			break;
		}
	} while (hIterWnd != NULL);

	return hRetWnd;
}

HHOOK MainDialog::SetGameWindowHook()
{
	if (m_hWindowHook != NULL) {
		IHookTrace(_T("window hook is already setted: hook id: %x"), m_hWindowHook);
		return m_hWindowHook;
	}

	HWND hWnd = GetGameHWnd();
	if (hWnd == NULL) {
		IHookTrace(_T("cannot get window handle"));
		return NULL;
	}
	IHookTrace(_T("hwnd: %x"), hWnd);

	DWORD dwThreadId = ::GetWindowThreadProcessId(hWnd, NULL);
	if (dwThreadId == 0) {
		IHookTrace(_T("cannot get thread process id： hwnd: %x"), hWnd);
		return NULL;
	}

	HMODULE hMod = ::GetModuleHandle(NULL);
	m_hWindowHook = ::SetWindowsHookEx(WH_CALLWNDPROC, (HOOKPROC)IHookWindowHookProc, hMod, dwThreadId);
	if (m_hWindowHook == NULL) {
		IHookTrace(_T("set hook failed: hwnd: %x, hmod: %x, thread id: %x"), hWnd, hMod, dwThreadId);
		return NULL;
	}
	IHookTrace(_T("set window hook success: hwnd: %x, hmod: %x, thread id: %x, hook id: %x"), hWnd, hMod, dwThreadId, m_hWindowHook);
	return m_hWindowHook;
}

BOOL MainDialog::UnSetGameWindowHook()
{
	if (m_hWindowHook == NULL) {
		IHookTrace(_T("window hook is not setted"));
		return TRUE;
	}

	BOOL ret = ::UnhookWindowsHookEx(m_hWindowHook);
	if (!ret) {
		IHookTrace(_T("unset window hook failed: hook id: %x"), m_hWindowHook);
	}

	IHookTrace(_T("unset window hook success: hook id: %x"), m_hWindowHook);
	m_hWindowHook = NULL;

	return ret;
}
