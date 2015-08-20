#pragma  once

#define EXE_PE_FILE_TYPE 'EXE'
#define DLL_PE_FILE_TYPE 'DLL'
#define SYS_PE_FILE_TYPE 'SYS'


#define EXE_SHELL_TAG	 L"EXE_001"
#define DLL_SHELL_TAG	 L"DLL_002"
#define SYS_SHELL_TAG	 L"SYS_003"


#include "stdio.h"
#include "ShellCodeStruct.h"
#include "PEIMAGE.h"

class UpShell
{
	public:
			UpShell();
			~UpShell();
			void		LoadShell(char* Module);
			void		LoadFile(char* Module);
			bool		TestPE();				//�����Ƿ����PE�ļ���ʽ
			ULONG		CheckHasUp();			//�ж��Ƿ��Ѿ��ӿ�
			ULONG		InitShellCodeData();	//��ʼ���ǵ���Ϣ
			PSHELLCODEINF  GetShellCodeInf(PIMAGE_DOS_HEADER m_pBuf , bool FindWhere ,ULONG size);
			ULONG		TestShellCodeInfo(PSHELLCODEINF pShellDataInf,long Set,\
										 ULONG AddressOfEntryPoint);
			ULONG			InitShellCodedata();
			ULONG			StartUpShell();
			ULONG			MovToFile( PIMAGE_SECTION_HEADER psFile, \
								PIMAGE_SECTION_HEADER psShell );
			void			SetShellCodeInf(PIMAGE_SECTION_HEADER pNewSec ,\
							PIMAGE_SECTION_HEADER PShellSec);
			void			SetPECheckSun();
	
	private:
			PSHELLCODEINF	 m_pShellCodeInfo;
			PEClass			PESHELL,PEFILE;
			ULONG			ShellCodeInfoOffsetSections;
			WCHAR* SHELLCODE_TAG;
	public:	
			PIMAGE_DOS_HEADER m_pshellBuf;
			PIMAGE_DOS_HEADER m_pfileBuf;
			
			
};

UpShell::UpShell()
{
	m_pShellCodeInfo = NULL;
}
UpShell::~UpShell()
{

}

void UpShell::LoadShell(char* Module)
{
	PESHELL.LoadPE(Module);
	m_pshellBuf = PESHELL.GetImageBuf();
}

void UpShell::LoadFile(char* Module)
{
	 PEFILE.LoadPE(Module);
	m_pfileBuf = PEFILE.GetImageBuf();
}

bool UpShell::TestPE()
{
	return (IS_A_PE == PEFILE.TestIsPE()) && \
			 (IS_A_PE == PESHELL.TestIsPE()); 
}

ULONG UpShell::CheckHasUp()
{
	
	ULONG FileLen , TempLen;
	PIMAGE_NT_HEADERS pNtHead;
	PUSHORT module = (PUSHORT)m_pfileBuf;
	PSHELLCODEINF pShellCodeInf;
	pNtHead = (PIMAGE_NT_HEADERS)((ULONG)m_pfileBuf + m_pfileBuf->e_lfanew);
	FileLen = PEFILE.GetFileSizex() / 2;
	TempLen = wcslen(EXE_SHELL_TAG);
	for( ULONG i = 0 ;i< (FileLen - TempLen) ; i++)
	{
		if( !memcmp(EXE_SHELL_TAG , &module[i] , TempLen  * 2) )		//�ҵ��Ǳ�ǩ
		{
				// �ӽṹ��Ԫ�� ��� �� �ṹ��ʼ��ַ
			pShellCodeInf = CONTAINING_RECORD( &module[i],SHELLCODEINF ,ShellCodeTag[0]);
				if( 0 == (TestShellCodeInfo(pShellCodeInf,0,\
											pNtHead->OptionalHeader.AddressOfEntryPoint)
						 )
						)
				{

					return 0;	
				}
		}
	}
	return 2;
}

void UpShell::SetPECheckSun()
{

	
	//�����������PE�ļ���У��ͣ�
	//��ΪSetPECheckSum1���Temp = (short)Temp + (short)pTemp[i];
	//��һ��VC++6.0���Ǳ���� add ָ������� adcָ��������ﲻ���������˻��ָ��
	PIMAGE_NT_HEADERS NtHeader;
	long CheckSum=0;
	ULONG dwsize , buff;
	dwsize = PEFILE.GetFileSizex();
	NtHeader = (IMAGE_NT_HEADERS*)((long)m_pfileBuf + m_pfileBuf->e_lfanew);
	NtHeader->OptionalHeader.CheckSum = 0;
	NtHeader->OptionalHeader.DataDirectory[11].Size = 0;
	NtHeader->OptionalHeader.DataDirectory[11].VirtualAddress = 0;
	buff = (ULONG)m_pfileBuf;
	__asm
	{
		pushad;
		mov ecx,dwsize;
		mov esi, buff;
		push ecx;
		inc ecx;
		shr ecx,1;
		xor ebx,ebx;
		clc;
loop001:
		lodsw;
		adc bx,ax;
		dec ecx;
		jnz loop001;
		pop eax;
		add eax,ebx;
		mov CheckSum,eax;
		popad;
	}
	NtHeader->OptionalHeader.CheckSum=CheckSum;
	printf("У���:  %d \n" ,CheckSum);
}


ULONG UpShell::TestShellCodeInfo(PSHELLCODEINF pShellDataInf,long Set \
										 ,ULONG AddressOfEntryPoint)
{

	//printf("a");

	if(0 == pShellDataInf->AddrGetNewPEInf)
	{
		return 0;
	}
	if(0 == pShellDataInf->AddrExeShellCodeMain)
	{
		return 0;
	}
	if(0 == pShellDataInf->AddrShellCodeInf)
	{
		return 0;
	}
	if(0 == pShellDataInf->AddrInlineShell1)
	{
		return 0;
	}
	if(0 == pShellDataInf->AddrInlineShell2)
	{
		return 0;
	}
	if(pShellDataInf->PEFileType != EXE_PE_FILE_TYPE )
	{
		return 0;
	}
	
	if(NULL != pShellDataInf->Module)
	{
		return 0;
	}
	if(Set)
	{
		
		if(0 != pShellDataInf->ShellCodeInfoRva)
		{
			//	printf("a");
			return 0;
		}
		if(0 != pShellDataInf->NewPEInf.AddressOfEntryPoint)
		{
			//	printf("b");
			return 0;
		}
		if(0 != pShellDataInf->Entry.AddressOfEntryPoint)
		{
			//	printf("c");
			return 0;
		}
		return 1;
	}
	
	if(0 == pShellDataInf->ShellCodeInfoRva)
	{
		return 0;
	}
	if(0 == pShellDataInf->NewPEInf.AddressOfEntryPoint)
	{
		return 0;
	}
	if(0 == pShellDataInf->Entry.AddressOfEntryPoint)
	{
		return 0;
	}
	if(AddressOfEntryPoint != pShellDataInf->Entry.AddressOfEntryPoint)
	{
		return 0;
	}
	return 1;
}

PSHELLCODEINF UpShell::GetShellCodeInf(PIMAGE_DOS_HEADER m_pBuf , bool FindWhere , ULONG size)
{
	
	ULONG FileLen , TempLen;
	PIMAGE_NT_HEADERS pNtHead;
	PUSHORT module = (PUSHORT)m_pBuf;
	PSHELLCODEINF pShellCodeInfo;
	pNtHead = (PIMAGE_NT_HEADERS)((ULONG)m_pBuf + m_pBuf->e_lfanew);
	FileLen = size / 2 /*PESHELL.GetFileSizex() / 2*/;
	TempLen = wcslen(EXE_SHELL_TAG);
	for( ULONG i = 0 ;i< (FileLen - TempLen) ; i++)
	{
	
/*
	if(FindWhere)
	{
		for( ULONG j = 0  ; (j < TempLen * 2 ) && (i<FileLen-TempLen * 2); j++)
		{
			printf("%C",module[j + i]);
		}
		printf("\n");
	}
	*/
	

		if( !memcmp(EXE_SHELL_TAG , &module[i] , TempLen*2 ) )		//�ҵ��Ǳ�ǩ
		{
			// �ӽṹ��Ԫ�� ��� �� �ṹ��ʼ��ַ
			pShellCodeInfo = CONTAINING_RECORD( &module[i],SHELLCODEINF ,ShellCodeTag[0]);
			
			if( pShellCodeInfo && FindWhere)

				return pShellCodeInfo;


			if( TestShellCodeInfo(pShellCodeInfo,1,0))
			{
				return pShellCodeInfo;	
			}
		}
	}
	return NULL;

}
// ��ȡ ������Ϣ��Rva
// ��ȡ ������Ϣ�ڽ���ƫ��


ULONG UpShell::InitShellCodedata()
{
	
	if( NULL == (m_pShellCodeInfo = GetShellCodeInf(m_pshellBuf ,false , PESHELL.GetFileSizex())))	
	{
		printf(" GetShellCodeInf error \n");
		return 1;
	}
	PIMAGE_SECTION_HEADER pImgSecHead = PESHELL.GetSectionByName("Mycode");

	if( NULL == pImgSecHead)
	{
		printf(" GetSectionByName error \n");
		return 1;
	}

	
	ShellCodeInfoOffsetSections = (ULONG) m_pShellCodeInfo - (ULONG)pImgSecHead;
	return 0;
}



ULONG	UpShell::MovToFile( PIMAGE_SECTION_HEADER psFile,PIMAGE_SECTION_HEADER psShell )
{

	UCHAR* buf = NULL;
	buf = new UCHAR [psShell->SizeOfRawData] ;
	if( NULL == buf)
		return 0;
	memset(buf , 0 , psShell->SizeOfRawData);
	
	PESHELL.ReadRaw(psShell->PointerToRawData , buf , psShell->SizeOfRawData);
	PEFILE.WriteRaw(psFile->PointerToRawData , buf ,  psShell->SizeOfRawData);

	return 1;
}



//��ڵ�ַ  ֱ��ָ��ExeMainWindows

void UpShell::SetShellCodeInf(PIMAGE_SECTION_HEADER pNewSec , PIMAGE_SECTION_HEADER PShellSec)
{

	PT_GetNewPeInf		 GetNewPeInf;
	PT_InlineShell1		 InlineShell;
	PSHELLCODEINF		 pShellCodeInf;
	PIMAGE_NT_HEADERS pNtHead;
	long   temp;
	pNtHead = (PIMAGE_NT_HEADERS)((ULONG)m_pfileBuf + m_pfileBuf->e_lfanew );

	pShellCodeInf = GetShellCodeInf(m_pfileBuf , true , PEFILE.GetFileSizex());

	if(pShellCodeInf == NULL)
	{
		printf("GetShellCodeInf����!!!\n ");
		return;
	}
//	pShellCodeInf = (PSHELLCODEINF)(ShellCodeInfoOffsetSections + (ULONG)pNewSec );

	//������Ҫ�޸�һ�� ���������ַ ��������Ϊ���˽��� ��������ƫ��
	temp = (ULONG) pShellCodeInf - pShellCodeInf->AddrShellCodeInf ; // ��ȥԭ���ı����ַ �õ���ֵ
	
	GetNewPeInf = (PT_GetNewPeInf)(temp + pShellCodeInf->AddrGetNewPEInf);
	InlineShell = (PT_InlineShell1)(temp + pShellCodeInf->AddrInlineShell1);

	pShellCodeInf->Entry.AddressOfEntryPoint = pNtHead->OptionalHeader.AddressOfEntryPoint;
	temp = (ULONG)(temp + pShellCodeInf->AddrExeShellCodeMain - (ULONG)PEFILE.GetImageBuf());
	temp = temp - pNewSec->PointerToRawData + pNewSec->VirtualAddress;
	PEFILE.SetEntry(temp);

	printf("�µ�OEP 0x%x",temp);
	//��յ��Ա�������
	pNtHead->OptionalHeader.DataDirectory[6].Size=0;
	pNtHead->OptionalHeader.DataDirectory[6].VirtualAddress=0;
	
	//��հ�Ȩ��������
	pNtHead->OptionalHeader.DataDirectory[7].Size=0;
	pNtHead->OptionalHeader.DataDirectory[7].VirtualAddress=0;
	
	//��ռ������ñ�������
	pNtHead->OptionalHeader.DataDirectory[10].Size=0;
	pNtHead->OptionalHeader.DataDirectory[10].VirtualAddress=0;
	
	//��հ������������
	pNtHead->OptionalHeader.DataDirectory[11].Size=0;
	pNtHead->OptionalHeader.DataDirectory[11].VirtualAddress=0;

    temp = (ULONG)pShellCodeInf - (ULONG)PEFILE.GetImageBuf(); //RA
	temp -= pNewSec->PointerToRawData;
	temp += pNewSec->VirtualAddress;  // RVA

	pShellCodeInf->ShellCodeInfoRva = temp;
	printf(" RVA ox%x\n" ,temp);	

//	InlineShell();					//��������

	GetNewPeInf(m_pfileBuf , &pShellCodeInf->NewPEInf);
	SetPECheckSun();

	PEFILE.FlushToFile();			//���浽�ļ�
}	
// ����Ƿ��Ѿ��ӹ���
// ��ȡ���ļ��пǵ�������Ϣ
// ���ӿ��ļ�����һ������
// �����ļ����½�
// ���ÿǵ�������Ϣ

ULONG UpShell::StartUpShell()
{
	
	if( CheckHasUp() == 0)
	{
		printf(" �Ѿ��ӹ�����\n");
		return 1;
	}
	if(InitShellCodedata())
	{
		printf("��ȡ���ļ�ʧ��");
		return 2;
	}

	PIMAGE_SECTION_HEADER pShellCode= NULL,pNewImgSecHead = NULL;
	pShellCode = PESHELL.GetSectionByName("Mycode");
	
	/*
	if( NULL == pShellCode)
		return -1;*/
	if(NULL ==  PEFILE.AddSections(".YLs",pShellCode->SizeOfRawData))
	{
		return 3;		
	}
	//�����¼�һ����������ͼˢ�£���Ҫ���»�ȡ ����ӳ��
	m_pfileBuf = PEFILE.GetImageBuf();
	pNewImgSecHead = PEFILE.GetSectionByName(".YLs");
	
	MovToFile(pNewImgSecHead , pShellCode);

	SetShellCodeInf(pNewImgSecHead , pShellCode );
		
return 4;
}