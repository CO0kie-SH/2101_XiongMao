// 2101_XiongMao.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "CVirus.h"

int main()
{
	//1. 获取驱动器名称
	char buf[100] = {};
	char* pTemp = buf;
	GetLogicalDriveStringsA(100, buf);
	// 把语言设置为中文
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
			printf("清理：%s\n", pTemp);
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

