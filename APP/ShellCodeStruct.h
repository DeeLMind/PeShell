#pragma once

#include "windows.h";
//���� ��ں���
// exe���
typedef long (__stdcall* EXEMAIN)(long ,long,long,long);
// dll���
typedef long (__stdcall* DLLMAIN)(long,long,long);
// sys���
typedef long (__stdcall* SYSMAIN)(long,long);

//��Ƕ������

#define DB(x) __asm _emit x

typedef struct _NEWPEINE  //�ӿǺ����PE�ļ���Ϣ
{
	long e_lfanew ;					//NTͷƫ��
	WORD NumberOfSections ;			//PE�ڸ���
	WORD SizeOfOptionHeader;		//PE��ѡͷ��С
	DWORD AddressOfEntryPoint;		//����OEP
	DWORD SectionAlign;				//�ڶ���
	DWORD FileAlign	;				//�ļ�����
	DWORD SizeofImage;				//ӳ���С
	DWORD SizeofHeaders;			//PEͷ��С
	DWORD NumberOfDataDirectory;	//����Ŀ¼��
	IMAGE_DATA_DIRECTORY DataDirectory[16]	;//����Ŀ¼
	DWORD SizeofRawData;			//���н����ļ������Ĵ�С
}NEWPEINF ,*PNEWPEINF;




typedef struct _SHELLCODEINF	//�ǳ����������Ϣ
{
	USHORT		ShellCodeTag[40]		;	//�ǳ����ǩ
	long		AddrGetNewPEInf;		//GetNewPEInf		�����ַ
	long		AddrExeShellCodeMain;	//�ǳ�����ں���	�����ַ
	long		AddrShellCodeInf	;	//SHELLCODEINF		�����ַ
	long		AddrInlineShell1	;	//�ǳ����ʼ��1		�����ַ
	long		AddrInlineShell2	;	//�ǳ����ʼ��2		�����ַ
	ULONG		PEFileType			;	//���ӿǳ���PE�ļ�����
	NEWPEINF	NewPEInf			;	//�ӿǺ����PE������Ϣ
	union
	{
		ULONG	AddressOfEntryPoint;	//����ӿ�ǰ���RVA
		EXEMAIN		EXEMain;			//�ӿ�ǰ exe���
		DLLMAIN		DLLMain;			//�ӿ�ǰ dll���
		SYSMAIN		SYSMain;			//�ӿ�ǰ sys���
	}Entry;	//�������

	long		ShellCodeInfoRva;	//�ӿǳ�������_SHELLCODEINF RVA
	union{
		PIMAGE_DOS_HEADER	Module;		//�ǳ�������ʱ�����	
		HINSTANCE			Hinstance;	//ͬ��
	};

	struct 
	{
		long	AddrExeShowWindows;		//ExeShowWindos �����ַ
		long	len				;		//��������
		UCHAR	SETDATA			;
	}SETDATA;

}SHELLCODEINF,*PSHELLCODEINF;


typedef void (__stdcall * PT_InlineShell1)();
typedef void (__stdcall * PT_GetNewPeInf)(PIMAGE_DOS_HEADER Module,OUT PNEWPEINF NewPeInf);