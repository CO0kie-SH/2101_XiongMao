#include "stdafx.h"
#include "CVirus.h"

#define defVirusSize 30001
#define defVirusMd5 "512301C535C88255C9A252FDF70B7A03"
#define defVirusHtm "<iframe src=http://www.ac86.cn/66/index.htm width=\"0\" height=\"0\"></iframe>"

CVirus::CVirus()
	:mpLast(0), mLastSize(0)
{
	mHeap = HeapCreate(0, 0, 0);
	this->HeapAlloc((LPVOID*)&this->mbuff, 255, 0);
	this->HeapAlloc(&this->mVirus, defVirusSize, 0);
	this->FixRegedit();
}

CVirus::~CVirus()
{
	HeapDestroy(mHeap);
}

BOOL CVirus::HeapAlloc(LPVOID * save, SIZE_T size, BOOL isZERO)
{
	LPVOID lpMem = ::HeapAlloc(mHeap,
		isZERO ? HEAP_ZERO_MEMORY : NULL, size);
	if (lpMem == 0) return 0;
	*save = lpMem;
	return TRUE;
}

BOOL CVirus::HeapFree(LPVOID * Address)
{
	return ::HeapFree(mHeap, 0, *Address);
}

void CVirus::EnumFile(LPCSTR DirPath, DWORD Deep)
{
	LPCH Path = new CHAR[MAX_PATH];
	wsprintfA(Path, "%s*", DirPath);
	WIN32_FIND_DATAA FindData = { 0 };
	HANDLE FindHandle = FindFirstFileA(Path, &FindData);
	if (FindHandle != INVALID_HANDLE_VALUE)
	{
		do {
			// 判断这个文件是不是目录
			if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				// . 当前目录  .. 上级目录 排除这两个
				if (strcmp(FindData.cFileName, ".") && strcmp(FindData.cFileName, ".."))
				{
					wsprintfA(Path, "%s%s\\", DirPath, FindData.cFileName);
					EnumFile(Path, Deep + 1);
				}
			}
			else
			{
				wsprintfA(mbuff, "%s%s", DirPath, FindData.cFileName);
				this->FileProc(DirPath, FindData);
			}
		} while (FindNextFileA(FindHandle, &FindData));
	}
	// 关闭句柄，注意没有用 CloseHandle
	FindClose(FindHandle);
	delete[] Path;
}

void CVirus::FileProc(LPCSTR DirPath, WIN32_FIND_DATAA& Info)
{
	if (strcmp(Info.cFileName, "Desktop_.ini") == 0)
	{
		printf("删除病毒 %d\t%s\n", DeleFile(mbuff), mbuff);
		return;
	}
	if (Info.nFileSizeLow == 81 && (
		strcmp(Info.cFileName, "autorun.inf") == 0))
	{
		printf("删除病毒 %d\t%s\n", DeleFile(mbuff), mbuff);
		return;
	}
	if (Info.nFileSizeLow == defVirusSize && (
		strcmp(Info.cFileName, "setup.exe") == 0 ||
		strcmp(Info.cFileName, "spo0lsv.exe") == 0
		)) {
		printf("删除病毒 %d\t%s\n", DeleFile(mbuff), mbuff);
		return;
	}
	if (Info.nFileSizeLow >= 74 && (
		_stricmp(PathFindExtensionA(Info.cFileName), ".htm") == 0
		)) {
		this->CheckHtm(DirPath, Info);
		return;
	}
	if (Info.nFileSizeLow >= 74 && (
		_stricmp(PathFindExtensionA(Info.cFileName), ".html") == 0
		)) {
		this->CheckHtm(DirPath, Info);
		return;
	}
	if (Info.nFileSizeLow >= defVirusSize && (
		_stricmp(PathFindExtensionA(Info.cFileName), ".exe") == 0
		)) {		//感染exe
		if (Info.nFileSizeLow == defVirusSize)
			printf("删除病毒 %d\t%s\n", DeleFile(mbuff), mbuff);
		else
			this->CheckExe(DirPath, Info);
		return;
	}
	if (Info.nFileSizeLow >= defVirusSize && (
		_stricmp(PathFindExtensionA(Info.cFileName), ".com") == 0
		)) {
		this->CheckExe(DirPath, Info);
		return;
	}
}

BOOL CVirus::CheckExe(LPCSTR DirPath, WIN32_FIND_DATAA & Info)
{
	if (Info.nFileSizeHigh > 0 ||
		Info.nFileSizeLow < defVirusSize)
		return 0;		//如果文件小于病毒大小，则返回
						//初始化数据
	char buff[255];

	//读取文件信息
	HANDLE handle = CreateFileA(mbuff, GENERIC_READ,		//打开文件句柄
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;
	DWORD dwRead;
	if (::ReadFile(handle, this->mVirus, defVirusSize, &dwRead, NULL) == FALSE
		|| dwRead != defVirusSize)
	{
		printf("无法打开文件：%s\n", mbuff);
		return 0;
	}

	//判断壳信息
	PWORD pDos = (PWORD)this->mVirus;
	if (*pDos != 0x5A4D || *(pDos + 6) != 0x4550)		//不是PE文件
		return 0;
	if (*(pDos + 10) != 0x5346 || *(pDos + 16) != 224)	//判断是不是FSG壳
		return 0;


	//处理缓冲区
	LPVOID lpMem = mpLast;
	if (mLastSize == 0 ||					//判断是否已有内存
		mLastSize < Info.nFileSizeLow) {	//判断内存是否可以复用
		if (lpMem)	this->HeapFree(&lpMem);				//释放旧的内存
		this->HeapAlloc(&lpMem, Info.nFileSizeLow, 0);	//申请新的内存
		this->mpLast = lpMem;							//标记缓冲区
		this->mLastSize = Info.nFileSizeLow;			//标记大小
	}

	//读取文件
	if (::ReadFile(handle, lpMem, Info.nFileSizeLow, &dwRead, NULL) == FALSE
		|| dwRead + defVirusSize != Info.nFileSizeLow)
	{
		CloseHandle(handle);						//无法得到文件内容
		printf("读取文件错误\t%s\n", mbuff);
		return 0;
	}
	CloseHandle(handle);

	//查询信息
	if (!GetExeInfo((LPBYTE)lpMem, dwRead, Info.cFileName))
	{
		printf("无法获取原信息\t%s\n", mbuff);
		return 0;
	}

	//还原文件
	sprintf_s(buff, 255, "%s%s", DirPath, Info.cFileName);
	handle = CreateFileA(buff, GENERIC_WRITE,		//打开文件句柄
		0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("修复文件失败。\n");
		return 0;
	}
	printf("写入 %15lu %s\t%s\n", dwRead,
		WriteFile(handle, lpMem, dwRead, &dwRead, 0) ?
		"成功" : "失败",
		buff);
	CloseHandle(handle);

	//覆盖源文件
	//strcpy_s(mbuff, 255, buff);
	//PathRemoveExtensionA(mbuff);
	return MoveFileExA(buff, mbuff,
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

BOOL CVirus::CheckHtm(LPCSTR DirPath, WIN32_FIND_DATAA & Info)
{
	if (Info.nFileSizeHigh > 0 ||
		Info.nFileSizeLow < 75)
		return 0;		//如果文件小于病毒大小，则返回
						//初始化数据

	//读取文件信息
	HANDLE handle = CreateFileA(mbuff, GENERIC_READ,		//打开文件句柄
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;
	DWORD dwRead, dwSize = Info.nFileSizeLow;
	

	//处理缓冲区
	LPVOID lpMem = mpLast;
	if (mLastSize == 0 ||					//判断是否已有内存
		mLastSize < Info.nFileSizeLow) {	//判断内存是否可以复用
		if (lpMem)	this->HeapFree(&lpMem);				//释放旧的内存
		this->HeapAlloc(&lpMem, Info.nFileSizeLow, 0);	//申请新的内存
		this->mpLast = lpMem;							//标记缓冲区
		this->mLastSize = Info.nFileSizeLow;			//标记大小
	}
	ZeroMemory(lpMem, dwSize + 1);

	//读取HTML
	if (::ReadFile(handle, lpMem, dwSize, &dwRead, NULL) == FALSE
		|| dwRead != dwSize)
	{
		printf("无法打开文件：%s\n", mbuff);
		return 0;
	}
	CloseHandle(handle);

	//判断HTML病毒
	LPSTR pStr = StrStrA((char*)lpMem, defVirusHtm);
	if (pStr==0)	return 0;	//没有感染
	*pStr = '\n';


	handle = CreateFileA(mbuff, GENERIC_WRITE,		//打开文件句柄
		0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("修复文件失败。\n");
		return 0;
	}
	BOOL bRet = WriteFile(handle, lpMem, dwSize - 75, &dwRead, 0);
	printf("写入 %lu %s\t%s\n", dwRead,
		bRet ? "成功" : "失败", mbuff);
	CloseHandle(handle);
	return bRet;
}

BOOL CVirus::FixRegedit()
{
	HKEY hKey;
	LSTATUS rCode;
	if ((rCode = RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey))
		== ERROR_SUCCESS) {
		rCode = RegDeleteValueA(hKey, "svcshare");
		RegCloseKey(hKey);
	}
	printf("删除自启动：\t%s\n", rCode == ERROR_SUCCESS ? "成功" : rCode == 2 ? "不存在" : "失败");
	if ((rCode = RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL", &hKey))
		== ERROR_SUCCESS) {
		int value = 1;
		rCode = RegSetKeyValueA(hKey, "CheckedValue", 0, REG_DWORD, &value, 4);
		RegCloseKey(hKey);
	}
	printf("开启隐藏文件：\t%s\n", rCode == ERROR_SUCCESS ? "成功" : "失败");
	return 1;
}

BOOL CVirus::DeleFile(LPCSTR Path)
{
	SetFileAttributesA(Path, FILE_ATTRIBUTE_NORMAL);
	return ::DeleteFileA(Path);
}

BOOL CVirus::GetExeInfo(LPBYTE MemAdd, DWORD & dwSize, LPSTR Name)
{
	BYTE i, *pBuf = MemAdd + dwSize - 1;
	if (*pBuf != 0x01)	return 0;		//不是病毒文件
	*pBuf = 0x00;


	//循环判断
	for (i = 1; i < 255; i++)
	{
		if (--pBuf == MemAdd)		//循环到头了
			return 0;
		else if (*pBuf == 0x02)		//遇到长度标记
			*pBuf = ' ';
		else if (*pBuf == 0x00)		//遇到标记
			break;
	}
	if (i == 255)	return 0;		//无法判断病毒标记
	memcpy(Name, pBuf + 1, 5);		//判断病毒
	Name[5] = 0;
	if (strcmp(Name, "WhBoy") != 0)	//不是Whboy
		return 0;

	pBuf += 6;
	sscanf_s((char*)pBuf, "%s %lu", Name, 255, &dwSize);
	return TRUE;
}
