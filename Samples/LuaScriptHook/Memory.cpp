#include "pch.h"
#include "Memory.h"

CMemory::CMemory()
{
}


CMemory::~CMemory()
{
}

BOOL byCompare(PBYTE pbyBase, PBYTE pbyPattern, PCHAR pszMask)
{
	for (; *pszMask; pszMask++, pbyBase++, pbyPattern++)
		if (*pszMask == 'x' && *pbyBase != *pbyPattern) return FALSE;

	return *pszMask == '\0';
}

DWORD CMemory::Search(DWORD dwBaseAddress, DWORD dwBaseSize, PBYTE pbyPattern, PCHAR pszMask)
{
	for (DWORD i = 0; i < dwBaseSize; i++) {
		if (byCompare((PBYTE)(dwBaseAddress + i), pbyPattern, pszMask)) {
			return (DWORD)(dwBaseAddress + i);
		}
	}

	return -1;
}

DWORD CMemory::Search(DWORD dwBaseAddress, DWORD dwBaseSize, PCHAR pszPattern)
{
	BYTE pbyPattern[MAX_PATH];
	CHAR pszMask[MAX_PATH];

	memset(pbyPattern, 0, MAX_PATH);
	memset(pszMask, '\0', MAX_PATH);

	size_t len = strlen(pszPattern), index = 0;
	for (size_t i = 0; i < len; i++) {
		BYTE ch = pszPattern[i];

		if (ch == ' ') {
			index++;
			continue;
		}

		if (ch >= '0' && ch <= '9') {
			pbyPattern[index] = pbyPattern[index] * 16 + ch - '0';
			pszMask[index] = 'x';
		}
		else if (ch >= 'a' && ch <= 'f') {
			pbyPattern[index] = pbyPattern[index] * 16 + ch - 'a' + 10;
			pszMask[index] = 'x';
		}
		else if (ch >= 'A' && ch <= 'F') {
			pbyPattern[index] = pbyPattern[index] * 16 + ch - 'A' + 10;
			pszMask[index] = 'x';
		}
		else {
			pszMask[index] = '?';
		}
	}

	return Search(dwBaseAddress, dwBaseSize, pbyPattern, pszMask);
}