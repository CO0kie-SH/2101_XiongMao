// 2101_XiongMao.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "CVirus.h"

int main()
{
	//1. ��ȡ����������
	char buf[100] = {};
	char* pTemp = buf;
	GetLogicalDriveStringsA(100, buf);
	// ����������Ϊ����
	setlocale(LC_ALL, "chs");
	system("mode 160,36");
	system("taskkill /f /im spo0lsv.exe /t");
	CVirus Virus;
	while (pTemp[0] != 0)
	{
		switch (GetDriveTypeA(pTemp))
		{
		case DRIVE_FIXED:
		case DRIVE_REMOTE:
			printf("����%s\n", pTemp);
			Virus.EnumFile(pTemp, 1);
			break;
		default:
			break;
		}
		pTemp += strlen(pTemp) + 1;
	}
	system("pause");
    return 0;
}

