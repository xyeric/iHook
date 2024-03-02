#pragma once

#include <afxwin.h>

class CMemory
{
public:
	CMemory();
	~CMemory();

	static DWORD Search(DWORD dwBaseAddress, DWORD dwSize, CHAR* pszPattern);
	static DWORD Search(DWORD dwBaseAddress, DWORD dwBaseSize, PBYTE bPattern, CHAR* pszMask);
};

