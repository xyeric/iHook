#include "assert.h"
#include "tchar.h"
#include "udis86.h"
#include "iHook.h"

CRITICAL_SECTION g_cs;

BOOL IHookInitState(IHOOK_STATE* pHookState)
{
	pHookState->hProcess = ::GetCurrentProcess();
	if (pHookState->hProcess == NULL) {
		return FALSE;
	}

	pHookState->type = IHOOK_TYPE_DEFAULT;
	pHookState->lpHookAddress = NULL;
	pHookState->lpCallbackAddress = NULL;
	pHookState->lpCallbackAddress = NULL;
	pHookState->lpCallbackParam = NULL;

	memset(&pHookState->regs, 0, sizeof(IHOOK_REGISTERS));
	memset(pHookState->byteBackupCode, 0x90, MAX_BACKUP_CODE_SIZE);
	memset(pHookState->szModuleName, 0, MAX_PATH * sizeof(TCHAR));
	memset(pHookState->szAPIName, 0, MAX_PATH * sizeof(TCHAR));

	::InitializeCriticalSection(&g_cs);

	return TRUE;
}

VOID IHookSetType(IHOOK_STATE* pHookState, IHOOK_TYPE type)
{
	pHookState->type = type;
}

VOID IHookSetAddress(IHOOK_STATE* pHookState, LPVOID lpHookAddress)
{
	pHookState->lpHookAddress = lpHookAddress;
}

VOID IHookSetCallback(IHOOK_STATE* pHookState, LPVOID lpHookCallback)
{
	pHookState->lpCallbackAddress = lpHookCallback;
}

VOID IHookSetCallbackParam(IHOOK_STATE* pHookState, LPVOID lpCallbackParam)
{
	pHookState->lpCallbackParam = lpCallbackParam;
}

VOID IHookSetModuleName(IHOOK_STATE* pHookState, PTCHAR pszModName)
{
	_tcscpy_s(pHookState->szModuleName, pszModName);
}

VOID IHookSetAPIName(IHOOK_STATE* pHookState, PTCHAR pszProcName)
{
	_tcscpy_s(pHookState->szAPIName, pszProcName);
}

BOOL __IHookBackupHookedCode(IHOOK_STATE* pHookState)
{
	assert(pHookState->hProcess != NULL);
	assert(pHookState->lpHookAddress != NULL);

	DWORD dwBufferSize = sizeof(pHookState->byteBackupCode) / sizeof(pHookState->byteBackupCode[0]);

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, MAX_BACKUP_CODE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook address error"));
	}

	BOOL bSuccess = ::ReadProcessMemory(pHookState->hProcess, LPVOID(pHookState->lpHookAddress), LPVOID(pHookState->byteBackupCode), dwBufferSize, NULL);
	if (!bSuccess) {
		IHookTrace(_T("read hook address memory error! process handle: 0x%x, hook address: 0x%x"), pHookState->hProcess, LPVOID(pHookState->lpHookAddress));
		return FALSE;
	}

	ud_t ud_obj;

	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, pHookState->byteBackupCode, dwBufferSize);
	ud_set_mode(&ud_obj, 32);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	ud_set_vendor(&ud_obj, UD_VENDOR_ANY);

	pHookState->dwBackupCodeSize = 0;
	while (pHookState->dwBackupCodeSize < 5) {
		pHookState->dwBackupCodeSize += ud_disassemble(&ud_obj);
		IHookTrace(_T("instruction disassebled: %s"), ud_insn_asm(&ud_obj));
	}

	IHookTrace(_T("%d byte disassebled."), pHookState->dwBackupCodeSize);

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, MAX_BACKUP_CODE_SIZE, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook address error"));
	}

	return TRUE;
}

#define HOOK_INLINE_DELEGATE_BUFFER_SIZE 0x3B
#define HOOK_INLINE_DELEGATE_CALLBACK_PARAM_PTR_OFFSET 0x02
#define HOOK_INLINE_DELEGATE_HOOK_STATE_PTR_OFFSET 0x07
#define HOOK_INLINE_DELEGATE_CALLBACK_PTR_OFFSET 0x0C
#define HOOK_INLINE_DELEGATE_BACKUP_CODE_OFFSET 0x24
#define HOOK_INLINE_DELEGATE_RETURN_CODE_OFFSET 0x34

void __declspec(naked) __IHookDelegate()
{
	__asm {
		pushad                                // 0x00(1)
		push 0x12345678                       // 0x01(5) push callback param ptr
		push 0x12345678                       // 0x06(5) push hook state ptr
		push 0x02345678                       // 0x0B(5) push callback address

		pop eax                               // 0x10(1), callback address
		pop ebx                               // 0x11(1), hook state ptr
		pop edx                               // 0x12(1), callback param ptr

		cld                                   // 0x13(1)
		mov esi, esp                          // 0x14(2), stack top ptr

		mov edi, ebx                          // 0x16(2), hook state ptr
		mov ecx, 0x20                         // 0x18(5), buffer size
		rep movsb                             // 0x1D(2)

		// stdcall, push parameters from right to left
		push edx                              // 0x20(1), push callback param
		push ebx                              // 0x1F(1), push hook state
		call eax                              // 0x21(2), callback

		popad                                 // 0x23(1)

		nop                                   // 0x24(0x10), backup code
		nop                                   // 0x25
		nop                                   // 0x26
		nop                                   // 0x27
		nop                                   // 0x28
		nop                                   // 0x29
		nop                                   // 0x2A
		nop                                   // 0x2B
		nop                                   // 0x2C
		nop                                   // 0x2D
		nop                                   // 0x2E
		nop                                   // 0x2F
		nop                                   // 0x30
		nop                                   // 0x31
		nop                                   // 0x32
		nop                                   // 0x33

		nop                                   // 0x34(5), jmp back
		nop                                   // 0x35
		nop                                   // 0x36
		nop                                   // 0x37
		nop                                   // 0x38
		nop                                   // 0x39
		nop                                   // 0x3A
		nop                                   // 0x3B
	}
}

LPVOID __IHookGetDelegateBodyAddress(LPVOID lpDelegateProc)
{
	IHookTrace(_T("hook delegate head address: 0x%x"), lpDelegateProc);

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(lpDelegateProc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook delegate head memory error"));
	}

	HANDLE hProcess = ::GetCurrentProcess();

	BYTE byteDelegateHead[5];
	BOOL bSuccess = ::ReadProcessMemory(hProcess, LPCVOID(lpDelegateProc), LPVOID(byteDelegateHead), 5, NULL);
	if (!bSuccess) {
		IHookTrace(_T("read hook address head memory error!"));
	}

	IHookTrace(_T("hook delegate head: 0x%x"), byteDelegateHead[0]);

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(lpDelegateProc, 5, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook head address error"));
	}

	if (byteDelegateHead[0] == 0xE9) {
		lpDelegateProc = LPVOID((DWORD)lpDelegateProc + *(DWORD*)(&byteDelegateHead[1]) + 5);
	}

	IHookTrace(_T("real hook delegate address resolved: 0x%x"), lpDelegateProc);

	return lpDelegateProc;
}

BOOL __IHookInitDelegate(IHOOK_STATE* pHookState)
{
	IHOOK_ASSERT(pHookState->type == IHOOK_TYPE_DEFAULT);
	IHOOK_ASSERT(pHookState->hProcess != NULL);
	IHOOK_ASSERT(pHookState->lpHookAddress != NULL);
	IHOOK_ASSERT(pHookState->lpCallbackAddress != NULL);
	IHOOK_ASSERT(pHookState->dwBackupCodeSize != 0);

	::EnterCriticalSection(&g_cs);

	// TODO dynamic delegate for multi hooks
	pHookState->lpDelegateAddress = __IHookGetDelegateBodyAddress(__IHookDelegate);

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(pHookState->lpDelegateAddress, HOOK_INLINE_DELEGATE_BUFFER_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook delegate memory error"));
	}

	// write hook state object pointer
	DWORD dwBytesWritten = 0;
	LPVOID lpHookStatePtr = LPVOID(pHookState);
	DWORD dwHookStatePtrAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_INLINE_DELEGATE_HOOK_STATE_PTR_OFFSET;
	BOOL bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwHookStatePtrAddress), &lpHookStatePtr, sizeof(DWORD), &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != sizeof(DWORD)) {
		IHookTrace(_T("write hook state pointer into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write hook state pointer into hook delegate memory success"));

	// write callback param pointer
	dwBytesWritten = 0;
	DWORD dwCallbackParamPtrAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_INLINE_DELEGATE_CALLBACK_PARAM_PTR_OFFSET;
	bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwCallbackParamPtrAddress), LPVOID(&pHookState->lpCallbackParam), sizeof(DWORD), &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != sizeof(DWORD)) {
		IHookTrace(_T("write callback param pointer into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write callback param pointer into hook delegate memory success!"));

	// write callback proc pointer
	dwBytesWritten = 0;
	DWORD dwCallbackPtrAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_INLINE_DELEGATE_CALLBACK_PTR_OFFSET;
	bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwCallbackPtrAddress), LPVOID(&pHookState->lpCallbackAddress), sizeof(DWORD), &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != sizeof(DWORD)) {
		IHookTrace(_T("write callback pointer into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write callback pointer into hook delegate memory success!"));

	// run backup code
	dwBytesWritten = 0;
	DWORD dwBackupCodeAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_INLINE_DELEGATE_BACKUP_CODE_OFFSET;

	// fix offset for call instruction
	BYTE byteBackupCode[MAX_BACKUP_CODE_SIZE];
	memcpy(byteBackupCode, pHookState->byteBackupCode, MAX_BACKUP_CODE_SIZE * sizeof(BYTE));
	if (byteBackupCode[0] == 0xE8) {
		*(DWORD*)(&byteBackupCode[1]) = (DWORD(pHookState->lpHookAddress) + *(DWORD*)(&byteBackupCode[1])) - dwBackupCodeAddress;
	}

	bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwBackupCodeAddress), LPVOID(byteBackupCode), pHookState->dwBackupCodeSize, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != pHookState->dwBackupCodeSize) {
		IHookTrace(_T("write backup code into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write backup code into hook delegate memory success!"));

	// jmp back to hook address
	DWORD dwReturnCodeAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_INLINE_DELEGATE_RETURN_CODE_OFFSET;

	BYTE bRetCode[HOOK_INLINE_DELEGATE_BUFFER_SIZE - HOOK_INLINE_DELEGATE_RETURN_CODE_OFFSET];
	memset(bRetCode, 0xCC, HOOK_INLINE_DELEGATE_BUFFER_SIZE - HOOK_INLINE_DELEGATE_RETURN_CODE_OFFSET);

	bRetCode[0] = 0xE9; //JMP
	*(DWORD*)(&bRetCode[1]) = DWORD(DWORD(pHookState->lpHookAddress) + pHookState->dwBackupCodeSize) - (DWORD)dwReturnCodeAddress - 5;

	dwBytesWritten = 0;
	bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwReturnCodeAddress), LPVOID(bRetCode), 5, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != 5) {
		IHookTrace(_T("write return code into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write return code into hook delegate memory success!"));

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(pHookState->lpDelegateAddress, HOOK_INLINE_DELEGATE_BUFFER_SIZE, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook address error"));
	}

	IHookTrace(_T("hook delegate init success: 0x%x"), pHookState->lpDelegateAddress);

	::LeaveCriticalSection(&g_cs);

	return TRUE;
}

#define HOOK_API_DELEGATE_BUFFER_SIZE 0x18
#define HOOK_API_DELEGATE_BACKUP_CODE_OFFSET 0x00
#define HOOK_API_DELEGATE_RETURN_CODE_OFFSET 0x10

void __declspec(naked) __IHookAPIDelegate()
{
	__asm {
		nop                                   // 0x00(0x10), backup code
		nop                                   // 0x01
		nop                                   // 0x02
		nop                                   // 0x03
		nop                                   // 0x04
		nop                                   // 0x29
		nop                                   // 0x2A
		nop                                   // 0x2B
		nop                                   // 0x2C
		nop                                   // 0x2D
		nop                                   // 0x2E
		nop                                   // 0x2F
		nop                                   // 0x30
		nop                                   // 0x31
		nop                                   // 0x32
		nop                                   // 0x33

		nop                                   // 0x34(5), jmp back
		nop                                   // 0x35
		nop                                   // 0x36
		nop                                   // 0x37
		nop                                   // 0x38
		nop                                   // 0x39
		nop                                   // 0x3A
		nop                                   // 0x3B
	}
}

BOOL __IHookInitAPIDelegate(IHOOK_STATE* pHookState)
{
	IHOOK_ASSERT(pHookState->type == IHOOK_TYPE_WIN32_API);
	IHOOK_ASSERT(pHookState->hProcess != NULL);
	IHOOK_ASSERT(pHookState->lpHookAddress != NULL);
	IHOOK_ASSERT(pHookState->lpCallbackAddress != NULL);
	IHOOK_ASSERT(pHookState->dwBackupCodeSize != 0);

	::EnterCriticalSection(&g_cs);

	pHookState->lpDelegateAddress = __IHookGetDelegateBodyAddress(__IHookAPIDelegate);

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(pHookState->lpDelegateAddress, HOOK_API_DELEGATE_BUFFER_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook delegate memory error"));
	}

	// run backup code
	DWORD dwBytesWritten = 0;
	DWORD dwBackupCodeAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_API_DELEGATE_BACKUP_CODE_OFFSET;

	// fix offset for call / jmp instruction
	BYTE byteBackupCode[MAX_BACKUP_CODE_SIZE];
	memcpy(byteBackupCode, pHookState->byteBackupCode, MAX_BACKUP_CODE_SIZE * sizeof(BYTE));
	if (byteBackupCode[0] == 0xE8 || byteBackupCode[0] == 0xE9) {
		*(DWORD*)(&byteBackupCode[1]) = (DWORD(pHookState->lpHookAddress) + *(DWORD*)(&byteBackupCode[1])) - dwBackupCodeAddress;
	}

	BOOL bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwBackupCodeAddress), LPVOID(byteBackupCode), pHookState->dwBackupCodeSize, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != pHookState->dwBackupCodeSize) {
		IHookTrace(_T("write backup code into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write backup code into hook delegate memory success!"));

	// jmp back to hook address
	DWORD dwReturnCodeAddress = DWORD(pHookState->lpDelegateAddress) + HOOK_API_DELEGATE_RETURN_CODE_OFFSET;

	BYTE bRetCode[HOOK_API_DELEGATE_BUFFER_SIZE - HOOK_API_DELEGATE_RETURN_CODE_OFFSET];
	memset(bRetCode, 0xCC, HOOK_API_DELEGATE_BUFFER_SIZE - HOOK_API_DELEGATE_RETURN_CODE_OFFSET);

	bRetCode[0] = 0xE9; //JMP
	*(DWORD*)(&bRetCode[1]) = DWORD(DWORD(pHookState->lpHookAddress) + pHookState->dwBackupCodeSize) - (DWORD)dwReturnCodeAddress - 5;

	dwBytesWritten = 0;
	bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(dwReturnCodeAddress), LPVOID(bRetCode), 5, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != 5) {
		IHookTrace(_T("write return code into hook delegate memory error!"));
		return FALSE;
	}
	IHookTrace(_T("write return code into hook delegate memory success!"));

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(pHookState->lpDelegateAddress, HOOK_API_DELEGATE_BUFFER_SIZE, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook address error"));
	}

	IHookTrace(_T("hook delegate init success: 0x%x"), pHookState->lpDelegateAddress);

	::LeaveCriticalSection(&g_cs);

	return TRUE;
}

LPVOID IHookGetAPIDelegate(IHOOK_STATE* pHookState)
{
	return (LPVOID)__IHookAPIDelegate;
}

BOOL __IHookInitHookDelegate(IHOOK_STATE* pHookState)
{
	if (pHookState->type == IHOOK_TYPE_WIN32_API) {
		return __IHookInitAPIDelegate(pHookState);
	}

	return __IHookInitDelegate(pHookState);
}

BOOL IHookSetHook(IHOOK_STATE* pHookState)
{
	::EnterCriticalSection(&g_cs);

	if (pHookState->type == IHOOK_TYPE_WIN32_API) {
		HMODULE hModule = ::GetModuleHandle(pHookState->szModuleName);
		if (hModule == NULL) return FALSE;

		pHookState->lpHookAddress = ::GetProcAddress(hModule, pHookState->szAPIName);

		// MSDN: The GetModuleHandle function returns a handle to a mapped module without incrementing its reference count.
		// FreeLibrary(hModule);
	}

	IHOOK_ASSERT(pHookState->hProcess != NULL);
	IHOOK_ASSERT(pHookState->lpHookAddress != NULL);
	IHOOK_ASSERT(pHookState->lpCallbackAddress != NULL);

	if (!__IHookBackupHookedCode(pHookState)) {
		IHookTrace(_T("backup hooked code error"));
		return FALSE;
	}

	if (!__IHookInitHookDelegate(pHookState)) {
		IHookTrace(_T("init hook delegate error"));
		return FALSE;
	}

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, pHookState->dwBackupCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook address error"));
	}

	BYTE byHookCode[MAX_BACKUP_CODE_SIZE]; //NOP
	memset(byHookCode, 0x90, MAX_BACKUP_CODE_SIZE);

	byHookCode[0] = 0xE9; // JMP


	// when using api hook, you should call delegate in the callback process
	if (pHookState->type == IHOOK_TYPE_WIN32_API) {
		*(DWORD*)(&byHookCode[1]) = DWORD(pHookState->lpCallbackAddress) - DWORD(pHookState->lpHookAddress) - 5;
	}
	else {
		// when using inline hook, you may need a delegate, to collect the registers' value
		*(DWORD*)(&byHookCode[1]) = DWORD(pHookState->lpDelegateAddress) - DWORD(pHookState->lpHookAddress) - 5;
	}

	DWORD dwBytesWritten = 0;
	BOOL bSuccess = ::WriteProcessMemory(pHookState->hProcess, LPVOID(pHookState->lpHookAddress), LPVOID(byHookCode), pHookState->dwBackupCodeSize, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != pHookState->dwBackupCodeSize) {
		IHookTrace(_T("write jmp code into hook address memory error!"));
		return FALSE;
	}

	IHookTrace(_T("write jmp code into hook address memory success!"));

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, pHookState->dwBackupCodeSize, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook address error"));
	}

	IHookTrace(_T("set hook success, process handle: 0x%x, hook address: 0x%x"), pHookState->hProcess, pHookState->lpHookAddress);

	::LeaveCriticalSection(&g_cs);

	return TRUE;
}

BOOL IHookUnsetHook(IHOOK_STATE* pHookState)
{
	assert(pHookState->hProcess != NULL);
	assert(pHookState->lpHookAddress != NULL);
	assert(pHookState->dwBackupCodeSize != 0);

	::EnterCriticalSection(&g_cs);

	DWORD dwOldProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, pHookState->dwBackupCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		IHookTrace(_T("remove the protect of hook address error"));
	}

	HANDLE hProcess = ::GetCurrentProcess();

	DWORD dwBytesWritten = 0;
	BOOL bSuccess = ::WriteProcessMemory(hProcess, LPVOID(pHookState->lpHookAddress), LPVOID(pHookState->byteBackupCode), pHookState->dwBackupCodeSize, &dwBytesWritten);
	if (!bSuccess || dwBytesWritten != pHookState->dwBackupCodeSize) {
		IHookTrace(_T("write hook address memory error!"));
		return FALSE;
	}

	DWORD dwNewProtect = 0;
	if (!::VirtualProtect(pHookState->lpHookAddress, pHookState->dwBackupCodeSize, dwOldProtect, &dwNewProtect)) {
		IHookTrace(_T("restore the protect of hook address error"));
	}

	IHookTrace(_T("reset hook success, process handle: 0x%x, hook address: 0x%x"), hProcess, pHookState->lpHookAddress);

	::LeaveCriticalSection(&g_cs);

	return TRUE;
}

DWORD IHookReadEax(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.eax : 0;
}

DWORD IHookReadEbx(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.ebx : 0;
}

DWORD IHookReadEcx(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.ecx : 0;
}

DWORD IHookReadEdx(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.edx : 0;
}

DWORD IHookReadEsp(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.esp : 0;
}

DWORD IHookReadEbp(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.ebp : 0;
}

DWORD IHookReadEsi(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.esi : 0;
}

DWORD IHookReadEdi(IHOOK_STATE* pHookState)
{
	return pHookState != NULL ? pHookState->regs.edi : 0;
}

DWORD IHookReadString(LPVOID lpAddress, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	memset(pszBuffer, 0x0, dwBufferSize);

	if (lpAddress != NULL) {
		try {
			memcpy(pszBuffer, (void*)lpAddress, dwBufferSize - 1);
			return _tcslen(pszBuffer);
		}
		catch (...) {
			return 0;
		}
	}

	return 0;
}

DWORD IHookReadEaxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.eax);
	}
	

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}
DWORD IHookReadEbxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.ebx);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEcxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.ecx);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEdxAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.edx);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEspAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.esp);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEbpAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.ebp);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEsiAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.esi);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

DWORD IHookReadEdiAsString(IHOOK_STATE* pHookState, TCHAR* pszBuffer, DWORD dwBufferSize)
{
	LPVOID lpAddress = NULL;
	if (pHookState != NULL) {
		lpAddress = LPVOID(pHookState->regs.edi);
	}

	return IHookReadString(lpAddress, pszBuffer, dwBufferSize);
}

VOID IHookTrace(const TCHAR* pszFormat, ...)
{
	TCHAR szMsg[MAX_PATH];
	va_list argList;
	va_start(argList, pszFormat);

	_vstprintf_s(szMsg, pszFormat, argList);

	TCHAR szMsgWithPrefix[MAX_PATH];
	_stprintf_s(szMsgWithPrefix, _T("[IHook] %s"), szMsg);

	::OutputDebugString(szMsgWithPrefix);

	va_end(argList);
}
