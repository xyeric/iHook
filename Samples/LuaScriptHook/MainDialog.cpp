// D:\Projects\VS\iHook\Samples\LuaScriptHook\CMainDialog.cpp: 实现文件
//

#include "pch.h"
#include "Launch.h"
#include "afxdialogex.h"
#include "MainDialog.h"


// CMainDialog 对话框

IMPLEMENT_DYNAMIC(CMainDialog, CDialogEx)

CMainDialog::CMainDialog(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_LAUNCH_DIALOG, pParent)
{

}

CMainDialog::~CMainDialog()
{
}

void CMainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CMainDialog, CDialogEx)
END_MESSAGE_MAP()


// CMainDialog 消息处理程序
