//	����ں���
//	����У��
//	����ʱ�������
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
	// ��ȡ����ʱ��ַ
	GetExeShellCodeData(&pShellDataInf,NULL,&pKerApi,&pUserAPi);

	//����ģ������ʱ����ַ  ����ʱ��ַ - RVA = ���ػ�ַ
	Module = (PIMAGE_DOS_HEADER )((long)pShellDataInf - pShellDataInf->ShellCodeInfoRva);
	
	pShellDataInf->Module = Module;

	// �� KerAPi �� UserAPi ���г�ʼ��

	if( 0 == InlineApiAddress())
	{
		return 0;
	}

	if( NULL == pUserAPi)
	{
		return 0 ;

	}
//	InlineShell1();						//���ܺ���


	// �ǳ��򴰿�
	if( 0 == ExeShellCodeShowWindows())
	{
	//	pUserAPi ->MessageBoxA(NULL,(char*)GetRunAddress("ȡ��"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}
	
	
	if( NULL == pKerApi)
	{
		return 0 ;

	}	

	//��ȡģ��PE��Ϣ

	GetNewPEInf(Module , &NewPEInf);

	// �Ƚ�PE�ļ��Ƿ�һ��


	if( 0 == CmpNewPEInf(&NewPEInf,& pShellDataInf->NewPEInf))
	{
		
		pUserAPi->MessageBoxA(NULL ,(char*)GetRunAddress("����У��ʧ��"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}

	
	if(0 == pShellDataInf->Entry.AddressOfEntryPoint)
	{
			
		pUserAPi->MessageBoxA(NULL,(char*)GetRunAddress("RVA ����"),NULL,0);
		pKerApi->ExitProcess(0);
		return 0;
	}
	
	//����ӿ�ǰ�������

	ExeMain =  (EXEMAIN) ( (long)Module +\
		(long)pShellDataInf->Entry.AddressOfEntryPoint) ;
	
//	InlineShell1();						// ���ܺ���

	return ExeMain(  DATA1 , DATA2 , DATA3 , DATA4 );
}




// ��/���ܺ���
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


//		�������ݶ�


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