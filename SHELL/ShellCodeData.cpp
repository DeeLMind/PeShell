#include "ShellCode.h"
#pragma  data_seg("Mydata")


#ifndef InlineShell2
#define InlineShell2 1
#endif

SHELLCODEINF ShellDataInf = 
{
		{ EXE_SHELL_TAG},
		(long)GetNewPEInf,
		(long)ExeShellCodeMain,
		(long)&ShellDataInf,
		(long)InlineShell1,
		(long)InlineShell2,
		EXE_PE_FILE_TYPE,
		{ 0 },
		0,
		0,
		NULL,
	{(long)ExeShellCodeShowWindows,0,0xAA}
};
// ȫ�ֱ���

 KERNEL32_API	     	KerApi = {0};
 USER32_API		    	UserApi= {0};
 SHELLWINDOWSINF    	 ExeWindowsInf[7] = {0};		//���ﲻд7 �ʹ���
