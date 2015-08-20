#pragma once
#include "STATICDATADEF.h"


//���� ��ں���
// exe���
typedef long (__stdcall* EXEMAIN)(long ,long,long,long);
// dll���
typedef long (__stdcall* DLLMAIN)(long,long,long);
// sys���
typedef long (__stdcall* SYSMAIN)(long,long);

//��Ƕ������

#define DB(x) __asm _emit x

//////////////////////////////////////
// �쳣����ṹ
//////////////////////////////////////


typedef struct _CODE_ERROR_RUN_INF
{
	unsigned long Eip;	//�쳣����� ����Ҫȥ�ĵط�
	unsigned long ExceptionCode; //�쳣������
}CODE_ERROR_RUN_INF , *PCODE_ERROR_RUN_INF;

// �쳣������

typedef struct _CODE_ERROR_ESP
{
	unsigned long FS0 ;				//��һ���쳣������
	unsigned long Exception_Handle;	//��ǰҪ���쳣������
	PCODE_ERROR_RUN_INF inf;		//������ɺ����ָ��
}CODE_ERROR_ESP ,* PCODE_ERROR_ESP;

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
	USHORT ShellCodeTag[40]		;	//�ǳ����ǩ
	long	AddrGetNewPEInf;		//GetNewPEInf		�����ַ
	long	AddrExeShellCodeMain;	//�ǳ�����ں���	�����ַ
	long	AddrShellCodeInf	;	//SHELLCODEINF		�����ַ
	long	AddrInlineShell1	;	//�ǳ����ʼ��1		�����ַ
	long	AddrInlineShell2	;	//�ǳ����ʼ��2		�����ַ
	ULONG	PEFileType			;	//���ӿǳ���PE�ļ�����
	NEWPEINF	NewPEInf		;	//�ӿǺ����PE������Ϣ
	
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


	 struct _pass						//��¼��������
	{
		char* buf;
		int len;
	};


	struct 
	{
		long	AddrExeShowWindows;		//ExeShowWindos �����ַ
		long	len				;		//��������
		UCHAR	SETDATA			;
	}SETDATA;

}SHELLCODEINF,*PSHELLCODEINF;


typedef struct _KERNEL32_API
{
	union
	{
		struct 
		{
			PT_GetProcAddress	GetProcessAddress;
			PTLoadLibraryA		LoadLibraryA;
			PTGetModuleHandleA	GetModuleHandleA;
			PTExitProcess		ExitProcess;
		};
		struct
		{
			char*	pcGetProcAddress;	
			char*	pcLoadLibraryA;			
			char*	pcGetModuleHandleA;			
			char*	pcExitProcess;			
		};
	};

}KERNEL32_API,*PKERNEL32_API;


typedef struct _USER32_API
{
	union
	{
		struct
		{
			PTRegisterClassExA     RegisterClassExA;
			PTCreateWindowExA      CreateWindowExA;
			PTShowWindow           ShowWindow;
			PTUpdateWindow         UpdateWindow;
			PTGetMessageA          GetMessageA;
			PTTranslateAccelerator TranslateAccelerator;
			PTTranslateMessage     TranslateMessage;
			PTDispatchMessageA     DispatchMessageA;
			PTGetDlgItemTextA      GetDlgItemTextA ;
			PTDefWindowProcA       DefWindowProcA;
			PTPostQuitMessage      PostQuitMessage;
			PTDestroyWindow        DestroyWindow;
			PTMessageBoxA          MessageBoxA;
		};

		struct
		{
			char* pcRegisterClassExA;
			char* pcCreateWindowExA;
			char* pcShowWindow;
			char* pcUpdateWindow;
			char* pcGetMessageA;
			char* pcTranslateAccelerator;
			char* pcTranslateMessage;
			char* pcDispatchMessageA;
			char* pcGetDlgItemTextA;
			char* pcDefWindowProcA;
			char* pcPostQuitMessage;
			char* pcDestroyWindow;
			char* pcMessageBoxA;
		};

	};

}USER32_API ,*PUSER32_API;

typedef struct _SHELLWINDOWSINF
{
	HWND hWnd;
	HMENU Id;
}SHELLWINDOWSINF ,*PSHELLWINDOWSINF;


