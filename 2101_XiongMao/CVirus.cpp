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
			// �ж�����ļ��ǲ���Ŀ¼
			if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				// . ��ǰĿ¼  .. �ϼ�Ŀ¼ �ų�������
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
	// �رվ����ע��û���� CloseHandle
	FindClose(FindHandle);
	delete[] Path;
}

void CVirus::FileProc(LPCSTR DirPath, WIN32_FIND_DATAA& Info)
{
	if (strcmp(Info.cFileName, "Desktop_.ini") == 0)
	{
		printf("ɾ������ %d\t%s\n", DeleFile(mbuff), mbuff);
		return;
	}
	if (Info.nFileSizeLow == 81 && (
		strcmp(Info.cFileName, "autorun.inf") == 0))
	{
		printf("ɾ������ %d\t%s\n", DeleFile(mbuff), mbuff);
		return;
	}
	if (Info.nFileSizeLow == defVirusSize && (
		strcmp(Info.cFileName, "setup.exe") == 0 ||
		strcmp(Info.cFileName, "spo0lsv.exe") == 0
		)) {
		printf("ɾ������ %d\t%s\n", DeleFile(mbuff), mbuff);
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
		)) {		//��Ⱦexe
		if (Info.nFileSizeLow == defVirusSize)
			printf("ɾ������ %d\t%s\n", DeleFile(mbuff), mbuff);
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
		return 0;		//����ļ�С�ڲ�����С���򷵻�
						//��ʼ������
	char buff[255];

	//��ȡ�ļ���Ϣ
	HANDLE handle = CreateFileA(mbuff, GENERIC_READ,		//���ļ����
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;
	DWORD dwRead;
	if (::ReadFile(handle, this->mVirus, defVirusSize, &dwRead, NULL) == FALSE
		|| dwRead != defVirusSize)
	{
		printf("�޷����ļ���%s\n", mbuff);
		return 0;
	}

	//�жϿ���Ϣ
	PWORD pDos = (PWORD)this->mVirus;
	if (*pDos != 0x5A4D || *(pDos + 6) != 0x4550)		//����PE�ļ�
		return 0;
	if (*(pDos + 10) != 0x5346 || *(pDos + 16) != 224)	//�ж��ǲ���FSG��
		return 0;


	//��������
	LPVOID lpMem = mpLast;
	if (mLastSize == 0 ||					//�ж��Ƿ������ڴ�
		mLastSize < Info.nFileSizeLow) {	//�ж��ڴ��Ƿ���Ը���
		if (lpMem)	this->HeapFree(&lpMem);				//�ͷžɵ��ڴ�
		this->HeapAlloc(&lpMem, Info.nFileSizeLow, 0);	//�����µ��ڴ�
		this->mpLast = lpMem;							//��ǻ�����
		this->mLastSize = Info.nFileSizeLow;			//��Ǵ�С
	}

	//��ȡ�ļ�
	if (::ReadFile(handle, lpMem, Info.nFileSizeLow, &dwRead, NULL) == FALSE
		|| dwRead + defVirusSize != Info.nFileSizeLow)
	{
		CloseHandle(handle);						//�޷��õ��ļ�����
		printf("��ȡ�ļ�����\t%s\n", mbuff);
		return 0;
	}
	CloseHandle(handle);

	//��ѯ��Ϣ
	if (!GetExeInfo((LPBYTE)lpMem, dwRead, Info.cFileName))
	{
		printf("�޷���ȡԭ��Ϣ\t%s\n", mbuff);
		return 0;
	}

	//��ԭ�ļ�
	sprintf_s(buff, 255, "%s%s", DirPath, Info.cFileName);
	handle = CreateFileA(buff, GENERIC_WRITE,		//���ļ����
		0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("�޸��ļ�ʧ�ܡ�\n");
		return 0;
	}
	printf("д�� %15lu %s\t%s\n", dwRead,
		WriteFile(handle, lpMem, dwRead, &dwRead, 0) ?
		"�ɹ�" : "ʧ��",
		buff);
	CloseHandle(handle);

	//����Դ�ļ�
	//strcpy_s(mbuff, 255, buff);
	//PathRemoveExtensionA(mbuff);
	return MoveFileExA(buff, mbuff,
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

BOOL CVirus::CheckHtm(LPCSTR DirPath, WIN32_FIND_DATAA & Info)
{
	if (Info.nFileSizeHigh > 0 ||
		Info.nFileSizeLow < 75)
		return 0;		//����ļ�С�ڲ�����С���򷵻�
						//��ʼ������

	//��ȡ�ļ���Ϣ
	HANDLE handle = CreateFileA(mbuff, GENERIC_READ,		//���ļ����
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
		return 0;
	DWORD dwRead, dwSize = Info.nFileSizeLow;
	

	//��������
	LPVOID lpMem = mpLast;
	if (mLastSize == 0 ||					//�ж��Ƿ������ڴ�
		mLastSize < Info.nFileSizeLow) {	//�ж��ڴ��Ƿ���Ը���
		if (lpMem)	this->HeapFree(&lpMem);				//�ͷžɵ��ڴ�
		this->HeapAlloc(&lpMem, Info.nFileSizeLow, 0);	//�����µ��ڴ�
		this->mpLast = lpMem;							//��ǻ�����
		this->mLastSize = Info.nFileSizeLow;			//��Ǵ�С
	}
	ZeroMemory(lpMem, dwSize + 1);

	//��ȡHTML
	if (::ReadFile(handle, lpMem, dwSize, &dwRead, NULL) == FALSE
		|| dwRead != dwSize)
	{
		printf("�޷����ļ���%s\n", mbuff);
		return 0;
	}
	CloseHandle(handle);

	//�ж�HTML����
	LPSTR pStr = StrStrA((char*)lpMem, defVirusHtm);
	if (pStr==0)	return 0;	//û�и�Ⱦ
	*pStr = '\n';


	handle = CreateFileA(mbuff, GENERIC_WRITE,		//���ļ����
		0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("�޸��ļ�ʧ�ܡ�\n");
		return 0;
	}
	BOOL bRet = WriteFile(handle, lpMem, dwSize - 75, &dwRead, 0);
	printf("д�� %lu %s\t%s\n", dwRead,
		bRet ? "�ɹ�" : "ʧ��", mbuff);
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
	printf("ɾ����������\t%s\n", rCode == ERROR_SUCCESS ? "�ɹ�" : rCode == 2 ? "������" : "ʧ��");
	if ((rCode = RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL", &hKey))
		== ERROR_SUCCESS) {
		int value = 1;
		rCode = RegSetKeyValueA(hKey, "CheckedValue", 0, REG_DWORD, &value, 4);
		RegCloseKey(hKey);
	}
	printf("���������ļ���\t%s\n", rCode == ERROR_SUCCESS ? "�ɹ�" : "ʧ��");
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
	if (*pBuf != 0x01)	return 0;		//���ǲ����ļ�
	*pBuf = 0x00;


	//ѭ���ж�
	for (i = 1; i < 255; i++)
	{
		if (--pBuf == MemAdd)		//ѭ����ͷ��
			return 0;
		else if (*pBuf == 0x02)		//�������ȱ��
			*pBuf = ' ';
		else if (*pBuf == 0x00)		//�������
			break;
	}
	if (i == 255)	return 0;		//�޷��жϲ������
	memcpy(Name, pBuf + 1, 5);		//�жϲ���
	Name[5] = 0;
	if (strcmp(Name, "WhBoy") != 0)	//����Whboy
		return 0;

	pBuf += 6;
	sscanf_s((char*)pBuf, "%s %lu", Name, 255, &dwSize);
	return TRUE;
}
