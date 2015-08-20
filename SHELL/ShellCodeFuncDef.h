//壳需要用到的函数定义
//入口函数
#pragma once

long __stdcall ExeShellCodeMain(long Data1,long Data2,long Data3,long Data4);
void __stdcall InlineShell1();



//////////////////////////////////////////////////////////////////////////
//ShellCodeRunError.cpp 提供运行时 异常处理 以及正确地址转换
// 获取运行时 程序地址 数据地址
PVOID __stdcall GetRunAddress(PVOID pData);
// 判断给定内存段是否可以被读取 ，返回0 表示失败
LONG  __stdcall  ExeProbeForRead(PVOID Address , long len);
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
//ShellCodePEImage.cpp 提供PE文件操作
//判断是否是PE文件 合法格式
long __stdcall TestPEImageExe(PIMAGE_DOS_HEADER Module,
	long Nt);	
//取得一个运行地址 所在 PE模块的 基地址 
PIMAGE_DOS_HEADER __stdcall GetPEImageModuleExe(PIMAGE_DOS_HEADER Module,
	long Nt );
//取得一个模块到处的函数地址
PVOID __stdcall GetProceAddressExe(PIMAGE_DOS_HEADER Module ,char* name);
//在内存中搜索制定模块名称的模块基地址
PIMAGE_DOS_HEADER __stdcall FromNameFindModule(char* name);
//获取一个PE信息
void __stdcall GetNewPEInf(PIMAGE_DOS_HEADER Module , PNEWPEINF NewPeInf);
// 比较两个PE文件
long __stdcall CmpNewPEInf(PNEWPEINF NewPEInf1 ,PNEWPEINF NewPEInf2);
//////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////
// ShellCodeCallFunction.cpp 提供给壳程序提供调用的函数
//字符串长度计算
long __stdcall StrLen(char* str);

// 字符串比较
long __stdcall StrCmp(char* str1 ,char* str2 ,long MAX);

//获取壳程序使用的数据地址

void __stdcall GetExeShellCodeData( OUT PSHELLCODEINF* pShellCodeInf,
									OUT PSHELLWINDOWSINF* pShellWindowsInf,
									OUT PKERNEL32_API* pKernel32_API,
									OUT PUSER32_API*	  pUser32_API);

// 对Kernel32 API 和User32 API 初始化
long __stdcall  InlineApiAddress();
// 壳程序弹出系统登录对话框
long __stdcall ExeShellCodeShowWindows();
void ExeShellCodeShowWIndowsEnd();
//////////////////////////////////////////////////////////////////////////