// MainDialog.cpp : 实现文件
//

#include "stdafx.h"
#include "MainDialog.h"
#include "afxdialogex.h"

// MainDialog 对话框

#pragma comment(lib,"Hook.lib")

IMPLEMENT_DYNAMIC(MainDialog, CDialog)

MainDialog::MainDialog()
	: CDialog(IDD_MAIN_WINDOW, NULL)
	, m_szHookAddress(_T(""))
	, m_szLuaString(_T(""))
	, m_bFilterLuaStringEanble(TRUE)
	, m_szFilterString(_T(""))
	, m_szTestLuaString(_T(""))
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

void __stdcall LuaHookCallback(IHookState* pHookState, LPVOID lpCallbackParam)
{
	MainDialog* dlg = (MainDialog*)lpCallbackParam;

	CString szLuaStr = "";
	try {
		szLuaStr.Format(_T("%s\r\n"), pHookState->regs.ecx);
	}
	catch (...) {}

	//IHookReadEcxAsString(pHookState, szLuaStr.GetBuffer(MAX_PATH), MAX_PATH);
	//szLuaStr.ReleaseBuffer();

	//szLuaStr += _T("\r\n");

	if (szLuaStr.GetLength() == 0 ||
		dlg->m_szLuaString.Find(szLuaStr) >= 0 ||
		(dlg->m_bFilterLuaStringEanble && dlg->m_szFilterString.Find(szLuaStr) >= 0)) {
		return;
	}

	IHookTrace(_T("eax: 0x%x, ebx: 0x%x, ecx: 0x%x"), (LPVOID)pHookState->regs.eax, (LPVOID)pHookState->regs.ebx, (LPVOID)pHookState->regs.ecx);

	dlg->m_szLuaString += szLuaStr;
	dlg->UpdateData(FALSE);
}

void MainDialog::OnBnClickedButtonSetHook()
{
	UpdateData(TRUE);

	DWORD dwHookAddress = StrToHex(m_szHookAddress.GetBuffer(0));
	m_szHookAddress.ReleaseBuffer();

	IHookTrace(_T("hook address: 0x%x"), dwHookAddress);

	if (!dwHookAddress) {
		MessageBox(_T("请输入Hook地址"), _T("错误提示"), MB_OK);
	}

	IHookInitState(&m_hookState);

	IHookSetHookAddress(&m_hookState, LPVOID(dwHookAddress));
	IHookSetCallback(&m_hookState, IHookCallback(LuaHookCallback));
	IHookSetCallbackParam(&m_hookState, LPVOID(this));

	IHookStartHook(&m_hookState);
}

void MainDialog::OnBnClickedButtonStopHook()
{
	IHookStopHook(&m_hookState);
}

void MainDialog::OnBnClickedButtonAddFilterString()
{
	m_szFilterString += m_szLuaString;
	m_szLuaString = "";

	UpdateData(FALSE);
}

void MainDialog::OnBnClickedButtonTestLuaString()
{
	//LPSTR buffer = m_szTestLuaString.GetBuffer(0);
	//DWORD callAddress = 0x00000000;
	//_asm {
	//	push buffer
	//	call callAddress
	//}
}

void MainDialog::OnBnClickedButtonSaveFilterString()
{
	CString szFileName = "";
	::GetCurrentDirectory(MAX_PATH, szFileName.GetBuffer(MAX_PATH));
	szFileName.ReleaseBuffer();
	szFileName += _T("LuaFilterString.txt");

	IHookTrace(_T("filter string saved success: %s"), szFileName.GetBuffer(0));
	szFileName.ReleaseBuffer();

	CFile file(szFileName, CFile::modeWrite | CFile::modeNoTruncate);

	file.Write(m_szFilterString, m_szFilterString.GetLength());

	file.Close();
}


void MainDialog::OnBnClickedCheckFilterLuaString()
{
	UpdateData(TRUE);
}
