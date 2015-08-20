//	壳入口函数
//	有自校验
//	运行时代码解密
//
#include "ShellCode.h"

#pragma  code_seg("Mycode")
long __stdcall ExeShellCodeMain(long DATA1 ,long DATA2 ,long DATA3 ,long DATA4)
{


	PIMAGE_DOS_HEADER Module;
	
	NEWPEINF NewPEInf = {0};
	PSHELLCODEINF pShellDataInf;
	PKERNEL32_API pKerApi;
	PUSER32_API pUserAPi;
	EXEMAIN		ExeMain;
	// 获取运行时地址
	GetExeShellCodeData(&pShellDataInf,NULL,&pKerApi,&pUserAPi);

	//计算模块运行时基地址  运行时地址 - RVA = 加载基址
	Module = (PIMAGE_DOS_HEADER )((long)pShellDataInf - pShellDataInf->ShellCodeInfoRva);
	
	pShellDataInf->Module = Module;

	// 对 KerAPi 和 UserAPi 进行初始化

	if( 0 == InlineApiAddress())
	{
		return 0;
	}

	if( NULL == pUserAPi)
	{
		return 0 ;

	}
//	InlineShell1();						//解密函数


	// 壳程序窗口
	if( 0 == ExeShellCodeShowWindows())
	{
	//	pUserAPi ->MessageBoxA(NULL,(char*)GetRunAddress("取消"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}
	
	
	if( NULL == pKerApi)
	{
		return 0 ;

	}	

	//获取模块PE信息

	GetNewPEInf(Module , &NewPEInf);

	// 比较PE文件是否一致


	if( 0 == CmpNewPEInf(&NewPEInf,& pShellDataInf->NewPEInf))
	{
		
		pUserAPi->MessageBoxA(NULL ,(char*)GetRunAddress("程序校验失败"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}

	
	if(0 == pShellDataInf->Entry.AddressOfEntryPoint)
	{
			
		pUserAPi->MessageBoxA(NULL,(char*)GetRunAddress("RVA 错误"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}
	
	//计算加壳前程序入口

	ExeMain =  (EXEMAIN) ( (long)Module +\
		(long)pShellDataInf->Entry.AddressOfEntryPoint) ;
	
//	InlineShell1();						// 加密函数

	return ExeMain(  DATA1 , DATA2 , DATA3 , DATA4 );
}




// 解/加密函数
void __stdcall SetDataFunc(PUCHAR p , long len ,UCHAR Key)
{
	while(len)
	{
		if( NULL == p)
		{

			DB(0xBE);
		}

		(*p) = (*p) ^ Key ;
		p++; len--;
	}
}


//		解密数据段


void __stdcall InlineShell1()
{

	PSHELLCODEINF pSHellDataInfo;
	PUCHAR	pBuffer; 
	LONG  len ;
	UCHAR key  = 0xAA;

	GetExeShellCodeData(&pSHellDataInfo ,NULL , NULL ,NULL );
	

	key = 0xAA;
	len = (long)ExeShellCodeShowWIndowsEnd - (long)ExeShellCodeShowWindows;
	pBuffer = (PUCHAR)ExeShellCodeShowWindows;
	pSHellDataInfo ->SETDATA.SETDATA = key ;
	pSHellDataInfo->SETDATA.len = len;
	pSHellDataInfo->SETDATA.AddrExeShowWindows = (long)pBuffer;

	pBuffer = (PUCHAR)GetRunAddress(pBuffer);

	if( NULL == pBuffer)
	{

		DB(0x81);
		DB(0xE3);
	}

	SetDataFunc(pBuffer , len , key);
}