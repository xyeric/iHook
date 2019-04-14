## iHook

Windowsƽ̨�µ�Hook�����⣬���Կ���̶�ȡĿ��������й����д��������λ�õļĴ���ֵ�Լ��ڴ�ֵ����ı�Ŀ����̵Ĵ����߼���

### ����ԭ��

iHook��ʵ��ԭ��Ϊinline hook�������кܶ���ܣ����ǽ�Hook���滻��һ��jmp�����䣬���������е�Hook��ʱ���Զ���ת���������õ�Hook��������У�ִ���괦����̺���ͨ��һ��jmp����������ԭ����λ�á�

��ͼƬ�����䣩

iHookֻ�����������еĽ���������Hook�������Ҫ�����ִ�У����Խ����������װ��һ����̬���ӿ�(dll)��Ȼ����ͨ��һ����ڳ��򣬽�iHookԶ��ע�뵽Ŀ����̡�(��ʾ���е�LuaHook)


### ʹ�ó���

### ���ٿ�ʼ

iHook�ṩ������Hookģʽ��һ����Ĭ��Hookģʽ����һ����Win32 API Hookģʽ��Ĭ��ģʽ�£����Զ��ڴ��������ַ����Hook�����ҿ����ڻص��ж�ȡ����ִ�е�Hookλ��ʱ�ļĴ������ڴ����ݵȵȣ����ܸ���ǿ�󣬵����ֶ��ҳ���ҪHook�ĵ�ַ��Win32 APIģʽ�£��������ָ����Win32 API����Hook�������ڻص���αװ���ؽ�������ٻص�����һЩ����Ĵ�����ٵ���ԭ����API��

**Ĭ��ģʽ:**
```C++
// Ĭ��ģʽ�£��ص��������ͱ���Ϊ��void __stdcall (*F)(IHOOK_STATE*, LPVOID);
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

**Win32APIģʽ:**
```C++
// ����Ŀ��API�����ͣ��ڻص��е���Ŀ��APIʱ��Ҫ�õ�
typedef HWND (WINAPI *GET_FOREGROUND_WINDOW)();

// Hook�ص�������Ҫ��Ŀ�꺯���������������ͱ���һ�£���������
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

### ��װ����

#### ���ذ�װ

�������䣩

#### �ֶ�����

##### ���뻷��

- ����ϵͳ��Windows x86(x64)
- ���뻷����Visual Studio 2017
- ����Ŀ�꣺Win32

### ����ṹ

����Ŀ�а�������Ŀ¼���ֱ��ǣ�
- iHook ��Hook���Ĵ��룬�ṩHook�����ӿڡ�
- Samples��ʾ�����롣

##### ��Ŀ����

���ڴ����ύ�Ĺ����У�������һЩ�Ƚ��ص������ļ�������ֱ�Ӵ�Github����������Ŀ�����뱾�ص������������죬����ڱ���֮ǰ�޸�һЩ��Ŀ������Ϣ�����������ܳ���

*1. ���п�*

��Ҫ����Ϊ�����߳�(MT)������Debugģʽ����Ҫ����Ϊ�����̵߳���(/MTd)��������༭���ܻᱨstdafx.hͷ�ļ�δ����Ĵ���

*1. ƽ̨�ܹ�*

����ֻ����x86��ʵ�֣�x64ƽ̨�¿��ܻ���ڼ��������⣬��ʹ�ܹ���������ͨ����Ҳ��һ���ܹ���ȷ���У�����ָ�볤�ȵı�����¶�ȡ�˴�����ڴ��ַ�ȵȣ�

*3. �ַ���*

Ĭ��������ַ���Ϊ��Unicode������������������룬��������Ŀ�����и����ַ���Ϊ��ASCII����
