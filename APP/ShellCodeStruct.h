#pragma once

#include "windows.h";
//定义 入口函数
// exe入口
typedef long (__stdcall* EXEMAIN)(long ,long,long,long);
// dll入口
typedef long (__stdcall* DLLMAIN)(long,long,long);
// sys入口
typedef long (__stdcall* SYSMAIN)(long,long);

//内嵌机器码

#define DB(x) __asm _emit x

typedef struct _NEWPEINE  //加壳后程序PE文件信息
{
	long e_lfanew ;					//NT头偏移
	WORD NumberOfSections ;			//PE节个数
	WORD SizeOfOptionHeader;		//PE可选头大小
	DWORD AddressOfEntryPoint;		//程序OEP
	DWORD SectionAlign;				//节对齐
	DWORD FileAlign	;				//文件对齐
	DWORD SizeofImage;				//映像大小
	DWORD SizeofHeaders;			//PE头大小
	DWORD NumberOfDataDirectory;	//数据目录数
	IMAGE_DATA_DIRECTORY DataDirectory[16]	;//数据目录
	DWORD SizeofRawData;			//所有节在文件对齐后的大小
}NEWPEINF ,*PNEWPEINF;




typedef struct _SHELLCODEINF	//壳程序的配置信息
{
	USHORT		ShellCodeTag[40]		;	//壳程序标签
	long		AddrGetNewPEInf;		//GetNewPEInf		编译地址
	long		AddrExeShellCodeMain;	//壳程序入口函数	编译地址
	long		AddrShellCodeInf	;	//SHELLCODEINF		编译地址
	long		AddrInlineShell1	;	//壳程序初始化1		编译地址
	long		AddrInlineShell2	;	//壳程序初始化2		编译地址
	ULONG		PEFileType			;	//被加壳程序PE文件类型
	NEWPEINF	NewPEInf			;	//加壳后程序PE基本信息
	union
	{
		ULONG	AddressOfEntryPoint;	//程序加壳前入口RVA
		EXEMAIN		EXEMain;			//加壳前 exe入口
		DLLMAIN		DLLMain;			//加壳前 dll入口
		SYSMAIN		SYSMain;			//加壳前 sys入口
	}Entry;	//程序入口

	long		ShellCodeInfoRva;	//加壳程序计算的_SHELLCODEINF RVA
	union{
		PIMAGE_DOS_HEADER	Module;		//壳程序运行时计算出	
		HINSTANCE			Hinstance;	//同上
	};

	struct 
	{
		long	AddrExeShowWindows;		//ExeShowWindos 编译地址
		long	len				;		//函数长度
		UCHAR	SETDATA			;
	}SETDATA;

}SHELLCODEINF,*PSHELLCODEINF;


typedef void (__stdcall * PT_InlineShell1)();
typedef void (__stdcall * PT_GetNewPeInf)(PIMAGE_DOS_HEADER Module,OUT PNEWPEINF NewPeInf);