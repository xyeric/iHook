// MainDialog.cpp : 实现文件
//

#include "stdafx.h"
#include "tlhelp32.h"
#include "MainDialog.h"
#include "Memory.h"
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

typedef DWORD lua_State;

typedef void (*lua_dostring_t)(lua_State* L, const char* szLuaStr);

lua_State* g_pGameLuaState;
lua_dostring_t lua_dostring = NULL;

lua_dostring_t GetLuaDoStringFunction() {
	if (lua_dostring) return lua_dostring;

	HMODULE hModule = ::GetModuleHandle("luaplus.dll");
	if (hModule == NULL) return NULL;

	lua_dostring = (lua_dostring_t)::GetProcAddress(hModule, "lua_dostring");
	if (lua_dostring == NULL) return NULL;

	::CloseHandle(hModule);

	return lua_dostring;
}

lua_State* GetGameLuaState()
{
	if (g_pGameLuaState) return g_pGameLuaState;

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	HANDLE hGameProcess = ::GetCurrentProcess();
	DWORD dwGameProcessID = ::GetProcessId(hGameProcess);

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwGameProcessID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) return NULL;

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return NULL;
	}

	DWORD dwGameModuleAddr = 0, dwGameModuleSize = 0;
	do {
		if (_tcsicmp(me32.szModule, "game.exe") == 0) {
			dwGameModuleAddr = (DWORD)me32.modBaseAddr;
			dwGameModuleSize = me32.modBaseSize;

			break;
		}
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);

	if (dwGameModuleAddr == 0 || dwGameModuleSize == 0) {
		IHookTrace(_T("[LuaHook] get lua state error."));
		return NULL;
	}

	DWORD dwRet = CMemory::Search(dwGameModuleAddr, dwGameModuleSize, (PCHAR)DEFAULT_LUA_STATE_FEATURE);
	if (dwRet == NULL) {
		IHookTrace(_T("[LuaHook] get lua state error."));
		return NULL;
	}

	DWORD dwLuaStateGetterBase = *(DWORD*)(dwRet + DEFAULT_LUA_STATE_FEATURE_OFFSET);

	DWORD pLuaState = NULL;

	__try {
		_asm
		{
			pushad
			mov ecx, dword ptr ds : [dwLuaStateGetterBase]
			mov eax, dword ptr ds : [ecx]
			mov eax, dword ptr ds : [eax]
			call dword ptr ds : [eax + 0x3C]
			mov eax, dword ptr ds : [eax]
			mov pLuaState, eax
			popad
		}
	}
	__except (1) {
		IHookTrace(_T("get lua state error."));
	}

	if (pLuaState != NULL) {
		g_pGameLuaState = (lua_State*)pLuaState;
		IHookTrace(_T("[LuaWorker] lua state base address: 0x%08X"), g_pGameLuaState);
	}

	return g_pGameLuaState;
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

//00BE8F90 | 55 | push ebp |
//00BE8F91 | 8BEC | mov ebp, esp |
//00BE8F93 | 6A FF | push FFFFFFFF |
//00BE8F95 | 68 F863D900 | push game.D963F8 |
//00BE8F9A | 64:A1 00000000 | mov eax, dword ptr fs : [0] |
//00BE8FA0 | 50 | push eax |
//00BE8FA1 | 81EC 28010000 | sub esp, 128 |
//00BE8FA7 | A1 D40A0D01 | mov eax, dword ptr ds : [10D0AD4] |
//00BE8FAC | 33C5 | xor eax, ebp |
//00BE8FAE | 8945 EC | mov dword ptr ss : [ebp - 14] , eax |
//00BE8FB1 | 53 | push ebx | ebx : "MiniMap_OnEvent(\"UPDATE_MAP\");"
//00BE8FB2 | 56 | push esi |
//00BE8FB3 | 57 | push edi | edi : "d荏"
//00BE8FB4 | 50 | push eax |
//00BE8FB5 | 8D45 F4 | lea eax, dword ptr ss : [ebp - C] |
//00BE8FB8 | 64 : A3 00000000 | mov dword ptr fs : [0] , eax |
//00BE8FBE | 8965 F0 | mov dword ptr ss : [ebp - 10] , esp |
//00BE8FC1 | 8BF1 | mov esi, ecx |
//00BE8FC3 | 8B0D 608F0D01 | mov ecx, dword ptr ds : [10D8F60] | 010D8F60 : &"d荏"
//00BE8FC9 | 8B5D 08 | mov ebx, dword ptr ss : [ebp + 8] | [ebp + 8] : "MiniMap_OnEvent(\"UPDATE_MAP\");"
//00BE8FCC | 8D85 D0FEFFFF | lea eax, dword ptr ss : [ebp - 130] |
//00BE8FD2 | 50 | push eax |
//00BE8FD3 | C745 FC 00000000 | mov dword ptr ss : [ebp - 4] , 0 |
//00BE8FDA | E8 D13BD3FF | call game.91CBB0 |
//00BE8FDF | 83C6 1C | add esi, 1C |

//00BE8FE2 | C645 FC 01 | mov byte ptr ss : [ebp - 4] , 1 | hook lua

//00BE8FE6 | 837E 14 10 | cmp dword ptr ds : [esi + 14] , 10 |
//00BE8FEA | 72 02 | jb game.BE8FEE |
//00BE8FEC | 8B36 | mov esi, dword ptr ds : [esi] |
//00BE8FEE | 803E 00 | cmp byte ptr ds : [esi] , 0 |
//00BE8FF1 | 8B3D 608F0D01 | mov edi, dword ptr ds : [10D8F60] | edi : "d荏", 010D8F60 : &"d荏"
//00BE8FF7 | 75 04 | jne game.BE8FFD |
//00BE8FF9 | 33C9 | xor ecx, ecx |
//00BE8FFB | EB 0E | jmp game.BE900B |
//00BE8FFD | 8BCE | mov ecx, esi |
//00BE8FFF | 8D51 01 | lea edx, dword ptr ds : [ecx + 1] |
//00BE9002 | 8A01 | mov al, byte ptr ds : [ecx] |
//00BE9004 | 41 | inc ecx |
//00BE9005 | 84C0 | test al, al |
//00BE9007 | 75 F9 | jne game.BE9002 |
//00BE9009 | 2BCA | sub ecx, edx |
//00BE900B | 51 | push ecx |
//00BE900C | 56 | push esi |
//00BE900D | 8D4F 28 | lea ecx, dword ptr ds : [edi + 28] | [edi + 28] : "MiniMap_Env"
//00BE9010 | E8 9BA7B5FF | call game.7437B0 |
//00BE9015 | 56 | push esi |
//00BE9016 | 68 206DF200 | push game.F26D20 | F26D20 : "setmetatable(_G, {__index = %s});"
//00BE901B | 8D85 E8FEFFFF | lea eax, dword ptr ss : [ebp - 118] |
//00BE9021 | 68 04010000 | push 104 |
//00BE9026 | 50 | push eax |
//00BE9027 | FF15 3804DC00 | call dword ptr ds : [<&_snprintf>] |
//00BE902D | 8B07 | mov eax, dword ptr ds : [edi] | edi : "d荏"
//00BE902F | 83C4 10 | add esp, 10 |
//00BE9032 | 8BCF | mov ecx, edi | edi : "d荏"
//00BE9034 | FF50 3C | call dword ptr ds : [eax + 3C] |
//00BE9037 | 8B35 E402DC00 | mov esi, dword ptr ds : [<&lua_dostring>] |
//00BE903D | 8D8D E8FEFFFF | lea ecx, dword ptr ss : [ebp - 118] |

// Hook Address Feature: C6 45 FC ?? 83 7E ?? ?? 72 02 8B 36 80 3E 00 8B 3D ?? ?? ?? ?? 75 04 33 C9 EB 0E 8B CE 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 51 56 8D 4F ?? E8 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 07 83 C4 10 8B CF FF 50 3C 8B 35 ?? ?? ?? ??
#define HOOK_ADDRESS_FEATURE _T("C6 45 FC ?? 83 7E ?? ?? 72 02 8B 36 80 3E 00 8B 3D ?? ?? ?? ?? 75 04 33 C9 EB 0E 8B CE 8D 51 01 8A 01 41 84 C0 75 F9 2B CA 51 56 8D 4F ?? E8 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 07 83 C4 10 8B CF FF 50 3C 8B 35 ?? ?? ?? ??")

/**
 * 开始Hook
 * 寻找相关地址：0142887F
 * x32dbg 底部命令行输入：bp lua_dostring，执行到返回，步进1次到 lua_dostring 调用处，通常游戏中会有多处调用 lua_dostring 的地方，可以重复前面的步骤，直到找到所有调用的地方，找到一处就设置下标签，便于后续定位
 * 从 lua_dostring 调用的地址往上找，找到函数入口处，打断点，步进，注意观察寄存器的值，碰到 lua 环境变量和函数调用字符串同时出现在两个寄存器时，就可以将该地址用作hook地址
 * 使用这个程序时，需要找到 eax 为环境变量，ebx 为函数调用的位置，因为这里的 hook 回调固定从这两个寄存器中读取 lua 调用信息的
 * 有时候找到的地址，hook 到的 lua 字符串会出现乱码，可以多试几个地方
 */
void MainDialog::OnBnClickedButtonSetHook()
{
	//UpdateData(TRUE);

	//DWORD dwHookAddress = StrToHex(m_szHookAddress.GetBuffer(0));
	//m_szHookAddress.ReleaseBuffer();

	//IHookTrace(_T("Hook address: 0x%x"), dwHookAddress);

	//if (!dwHookAddress) {
	//	MessageBox(_T("请输入Hook地址"), _T("错误提示"), MB_OK);
	//	return;
	//}

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	HANDLE hGameProcess = ::GetCurrentProcess();
	DWORD dwGameProcessID = ::GetProcessId(hGameProcess);

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwGameProcessID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) return;

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return;
	}

	DWORD dwGameModuleAddr = 0, dwGameModuleSize = 0;
	do {
		if (_tcsicmp(me32.szModule, "game.exe") == 0) {
			dwGameModuleAddr = (DWORD)me32.modBaseAddr;
			dwGameModuleSize = me32.modBaseSize;

			break;
		}
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);

	if (dwGameModuleAddr == 0 || dwGameModuleSize == 0) {
		IHookTrace(_T("[LuaHook] get lua state error."));
		return;
	}

	DWORD dwHookAddress = CMemory::Search(dwGameModuleAddr, dwGameModuleSize, HOOK_ADDRESS_FEATURE);
	IHookTrace(_T("Hook address: 0x%x"), dwHookAddress);

	if (dwHookAddress < dwGameModuleAddr || dwHookAddress > dwGameModuleAddr + dwGameModuleSize) {
		return;
	}

	IHookSetType(&m_hookState, IHOOK_TYPE_DEFAULT);
	IHookSetAddress(&m_hookState, LPVOID(dwHookAddress));
	IHookSetCallback(&m_hookState, LPVOID(LuaHookCallback));
	IHookSetCallbackParam(&m_hookState, LPVOID(this));

	// IHookSetHook(&m_hookState);

	// IHookSetType(&m_hookState, IHOOK_TYPE_WIN32_API);
	// IHookSetModuleName(&m_hookState, _T("user32.dll"));
	// IHookSetAPIName(&m_hookState, _T("GetForegroundWindow"));
	// IHookSetCallback(&m_hookState, FakeGetForegroundWindow);

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
	HMODULE hModule = NULL;

	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)LuaHookCallback, &hModule);
	if (hModule == NULL) return;

	TCHAR szPath[MAX_PATH];
	DWORD dwIniPathLength = ::GetModuleFileName(hModule, szPath, MAX_PATH);

	if (::FreeLibrary(hModule) == FALSE) {
		IHookTrace(_T("get work directory failed, cannot free module handle"));
	}
	hModule = NULL;

	TCHAR* pFind = _tcsrchr(szPath, '\\');
	if (pFind == NULL) {
		return;
	}

	*pFind = '\0';

	CString szFileName = szPath;
	szFileName += _T("\\LuaFilterString.txt");

	IHookTrace(_T("filter string saved at: %s"), szFileName.GetBuffer(0));
	szFileName.ReleaseBuffer();

	CFile file(szFileName, CFile::modeRead | CFile::modeWrite | CFile::modeNoTruncate);

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

#		/**
		 * 寻找相关地址：
		 * x32dbg 底部命令行输入：bp lua_dostring，执行到返回，步进1次到调用处，往上翻
		 * luaState：寻找到 call dword ptr ds:[eax+3C]，往前找到eax来源，能够拿到一个静态的地址
		 * lua_dostring call 地址：找到call lua_dostring的位置，注意查看call的方式，通常会有两种方式：
		 *   call dword ptr ds:[0xxxxx]，这种方式，方括号中的地址可能是反解析的结果，call 地址可以查看汇编前面的机器码（注意大小端的区别，字节是反过来的），也可以按空格键查看汇编源码，从中获取
		 *   call esi，这种方式，需要找到esi的来源
		 */
		TCHAR* pszLuaStr = (TCHAR*)lpArg->lParam;

		lua_State* pLuaState = GetGameLuaState();
		lua_dostring_t lua_dostring = GetLuaDoStringFunction();

		lua_dostring(pLuaState, pszLuaStr);

		//_asm {
		//	pushad
		//	mov ecx, dword ptr ds : [0x1918F60] // luaState
		//	mov eax, dword ptr ds : [ecx]
		//	call dword ptr ds : [eax + 0x3C]
		//	push pszLuaStr
		//	push dword ptr ds : [eax]
		//	call dword ptr ds : [0x016002E4] // lua_dostring
		//	add esp, 8
		//	popad
		//}

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
