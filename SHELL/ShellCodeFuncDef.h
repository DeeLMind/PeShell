//����Ҫ�õ��ĺ�������
//��ں���
#pragma once

long __stdcall ExeShellCodeMain(long Data1,long Data2,long Data3,long Data4);
void __stdcall InlineShell1();



//////////////////////////////////////////////////////////////////////////
//ShellCodeRunError.cpp �ṩ����ʱ �쳣���� �Լ���ȷ��ַת��
// ��ȡ����ʱ �����ַ ���ݵ�ַ
PVOID __stdcall GetRunAddress(PVOID pData);
// �жϸ����ڴ���Ƿ���Ա���ȡ ������0 ��ʾʧ��
LONG  __stdcall  ExeProbeForRead(PVOID Address , long len);
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
//ShellCodePEImage.cpp �ṩPE�ļ�����
//�ж��Ƿ���PE�ļ� �Ϸ���ʽ
long __stdcall TestPEImageExe(PIMAGE_DOS_HEADER Module,
	long Nt);	
//ȡ��һ�����е�ַ ���� PEģ��� ����ַ 
PIMAGE_DOS_HEADER __stdcall GetPEImageModuleExe(PIMAGE_DOS_HEADER Module,
	long Nt );
//ȡ��һ��ģ�鵽���ĺ�����ַ
PVOID __stdcall GetProceAddressExe(PIMAGE_DOS_HEADER Module ,char* name);
//���ڴ��������ƶ�ģ�����Ƶ�ģ�����ַ
PIMAGE_DOS_HEADER __stdcall FromNameFindModule(char* name);
//��ȡһ��PE��Ϣ
void __stdcall GetNewPEInf(PIMAGE_DOS_HEADER Module , PNEWPEINF NewPeInf);
// �Ƚ�����PE�ļ�
long __stdcall CmpNewPEInf(PNEWPEINF NewPEInf1 ,PNEWPEINF NewPEInf2);
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
// ShellCodeCallFunction.cpp �ṩ���ǳ����ṩ���õĺ���
//�ַ������ȼ���
long __stdcall StrLen(char* str);

// �ַ����Ƚ�
long __stdcall StrCmp(char* str1 ,char* str2 ,long MAX);

//��ȡ�ǳ���ʹ�õ����ݵ�ַ

void __stdcall GetExeShellCodeData( OUT PSHELLCODEINF* pShellCodeInf,
									OUT PSHELLWINDOWSINF* pShellWindowsInf,
									OUT PKERNEL32_API* pKernel32_API,
									OUT PUSER32_API*	  pUser32_API);

// ��Kernel32 API ��User32 API ��ʼ��
long __stdcall  InlineApiAddress();
// �ǳ��򵯳�ϵͳ��¼�Ի���
long __stdcall ExeShellCodeShowWindows();
void ExeShellCodeShowWIndowsEnd();
//////////////////////////////////////////////////////////////////////////