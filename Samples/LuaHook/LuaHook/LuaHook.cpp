// LuaHook.cpp: 定义 DLL 的初始化例程。
//

#include "stdafx.h"
#include "LuaHook.h"
#include "MainDialog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CLuaHookApp

BEGIN_MESSAGE_MAP(CLuaHookApp, CWinApp)
END_MESSAGE_MAP()


// CLuaHookApp 构造

CLuaHookApp::CLuaHookApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的 CLuaHookApp 对象

CLuaHookApp theApp;

BOOL WINAPI LuaHookAppThreadProc()
{
	MainDialog* mainDlg = new MainDialog();
	mainDlg->DoModal();

	delete mainDlg;

	::FreeLibraryAndExitThread(theApp.m_hInstance, 0);

	return TRUE;
}

// CLuaHookApp 初始化

BOOL CLuaHookApp::InitInstance()
{
	CWinApp::InitInstance();

	LPTHREAD_START_ROUTINE proc = (LPTHREAD_START_ROUTINE)LuaHookAppThreadProc;
	::CreateThread(NULL, 0, proc, NULL, NULL, NULL);

	return TRUE;
}
