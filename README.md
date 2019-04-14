## iHook

Windows平台下的Hook操作库，可以跨进程读取目标进程运行过程中代码段任意位置的寄存器值以及内存值，或改变目标进程的代码逻辑。

### 工作原理

iHook的实现原理为inline hook，网上有很多介绍，就是将Hook点替换成一条jmp汇编语句，当程序运行到Hook点时，自动跳转到我们设置的Hook处理过程中，执行完处理过程后，再通过一个jmp汇编语句跳回原来的位置。

（图片待补充）

iHook只能在自身运行的进程中设置Hook，如果需要跨进程执行，可以将操作界面封装成一个动态链接库(dll)，然后再通过一个入口程序，将iHook远程注入到目标进程。(见示例中的LuaHook)


### 使用场景

### 快速开始

iHook提供了两种Hook模式，一种是默认Hook模式，另一种是Win32 API Hook模式。默认模式下，可以对内存中任意地址进行Hook，并且可以在回调中读取程序执行到Hook位置时的寄存器，内存数据等等，功能更加强大，但得手动找出需要Hook的地址；Win32 API模式下，可以针对指定的Win32 API进行Hook，可以在回调中伪装返回结果，或再回调中做一些特殊的处理后再调用原来的API。

**默认模式:**
```C++
// 默认模式下，回调函数类型必须为：void __stdcall (*F)(IHOOK_STATE*, LPVOID);
void __stdcall HookCallback(IHOOK_STATE* pHookState, LPVOID lpCallbackParam)
{
	MainDialog* dlg = (MainDialog*)lpCallbackParam;

	dlg->m_szLuaString.Format(_T("eax: %d\r\n"), IHookReadEax(pHookState));
	dlg->SendMessage(WM_UPDATEDATA, FALSE);
}

IHOOK_STATE hookState;
IHookInitState(&hookState);

IHookSetAddress(&hookState, LPVOID(dwHookAddress));
IHookSetCallback(&hookState, LPVOID(LuaHookCallback));
IHookSetCallbackParam(&hookState, LPVOID(this));

IHookSetHook(&hookState);

// ...
IHookUnsetHook(&hookState);
```

**Win32API模式:**
```C++
// 定义目标API的类型，在回调中调用目标API时需要用到
typedef HWND (WINAPI *GET_FOREGROUND_WINDOW)();

// Hook回调函数需要和目标函数参数、返回类型保持一致，否则会出错
HWND WINAPI FakeGetForegroundWindow()
{
	//return 0x1212da; // fake caller for special purpose

	GET_FOREGROUND_WINDOW GetForegroundWindow = (GET_FOREGROUND_WINDOW)IHookGetAPIDelegate(NULL);
	HWND ret = GetForegroundWindow();

	IHookTrace(_T("GetForegroundWindow: 0x%x"), ret);

	return ret;
}

IHOOK_STATE hookState;
IHookInitState(&hookState);

IHookSetType(&hookState, IHOOK_TYPE_WIN32_API);
IHookSetModuleName(&hookState, _T("user32.dll"));
IHookSetAPIName(&hookState, _T("GetForegroundWindow"));
IHookSetCallback(&hookState, FakeGetForegroundWindow);

IHookSetHook(&hookState);

// ...
IHookUnsetHook(&hookState);
```

### 安装构建

#### 下载安装

（待补充）

#### 手动编译

##### 编译环境

- 操作系统：Windows x86(x64)
- 编译环境：Visual Studio 2017
- 编译目标：Win32

### 代码结构

该项目中包含三个目录，分别是：
- iHook ，Hook核心代码，提供Hook操作接口。
- Samples，示例代码。

##### 项目配置

由于代码提交的过程中，忽略了一些比较重的配置文件，所以直接从Github拉下来的项目配置与本地的配置有所差异，因此在编译之前修改一些项目配置信息，否则编译可能出错。

*1. 运行库*

需要更改为“多线程(MT)”，在Debug模式下需要更改为“多线程调试(/MTd)”，否则编辑可能会报stdafx.h头文件未引入的错误。

*1. 平台架构*

代码只做了x86的实现，x64平台下可能会存在兼容性问题，即使能够正常编译通过，也不一定能够正确运行（比如指针长度的变更导致读取了错误的内存地址等等）

*3. 字符集*

默认情况下字符集为“Unicode”，如编译结果出现乱码，可以在项目属性中更改字符集为“ASCII”。
