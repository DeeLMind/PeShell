#include "ShellCode.h"

// �ṩPE�ļ�����
#pragma code_seg("Mycode")


#define  ISPEFILE 10

// PE�ļ���ַȷ������

long __stdcall TestPEImageExe(PIMAGE_DOS_HEADER Module, long Nt)
{

	PIMAGE_NT_HEADERS pNtHead;
	long ret;

	ret = 0 ; // 0
	do 
	{
		if( 0x10000 >= (ULONG) Module)
		{
			break;
		}
		ret ++ ; // 1

		if( 0 == Nt)
		{
			if( 0xFFFF & (ULONG) Module)	//�ڴ�û����
			{
				break;
			}
		}
		ret ++; //2
		if( IMAGE_DOS_SIGNATURE != Module->e_magic )
		{
			break;
		}
		ret ++; // 3
		// nt ͷƫ��Ϊ8�ı���
		if( 7 & (Module->e_lfanew))
		{
			break;
		}
		ret ++; //4
		if(0x1000 <= Module->e_lfanew)
		{
			break;
		}
		ret ++; //5

		pNtHead = (PIMAGE_NT_HEADERS)((long)Module->e_lfanew + (long)Module);
		if (IMAGE_NT_SIGNATURE != pNtHead->Signature)
		{
			break;
		}
		ret ++; //6
		if( 1 > pNtHead->FileHeader.NumberOfSections 
			|| pNtHead->FileHeader.NumberOfSections > 96)
		{

			break;
		}
		ret ++ ; // 7
		//������Ч��exe pe�ļ�����
		if(!((0x100&pNtHead->FileHeader.Characteristics)
			&&(0==(0x3000&pNtHead->FileHeader.Characteristics))))
		{
			//����dll�ļ�����
			if(!((0x100&pNtHead->FileHeader.Characteristics)
				&&(0x2000&pNtHead->FileHeader.Characteristics)))
			{
				//���������ļ�����
				if(!(0x1000&pNtHead->
					FileHeader.Characteristics))
				{
					break;
				}
			}
		}
		ret ++ ;  // 8
		// PE 32
		if(0x10B != pNtHead->OptionalHeader.Magic)
		{
			break;
		}

		ret ++ ; // 9
							// ӳ��ʱ��ʱ���սڶ���
		if( pNtHead->OptionalHeader.SizeOfImage 	& (pNtHead->OptionalHeader.SectionAlignment - 1))
		{

			break;
		}


		ret ++;	// ret =10
		break;
	}while (0);
	return ret;
}


//	1�Ƚ���ŵõ� ��ǰ����
//  2������ֵ�ҵ� ˳����е������±�
//	3�����±� ������������ַ��


// ���һ��ģ�鵼���ĺ�����ַ
PVOID __stdcall GetProceAddressExe(PIMAGE_DOS_HEADER Module ,char* name)
{
	PVOID ret;
	long NameLen , i;
	long* FuncNameRva , *pFuncRva;
	USHORT *pFuncOld;
	char * TempFuncName;

	PIMAGE_NT_HEADERS pNtHead;
	PIMAGE_DATA_DIRECTORY pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExpDir;
	do 
	{
		ret = NULL;

		NameLen = StrLen(name);
		if ( 0 == NameLen)
		{
			break;
		}

		if( (!name) || (0 == *name ) )
		{
			break;
		}
		//��λPE��ǩ
		pNtHead = (PIMAGE_NT_HEADERS )(Module->e_lfanew + (long)Module);
		pDataDir = pNtHead->OptionalHeader.DataDirectory;

		// �Ƿ��������
		if(! (pDataDir->VirtualAddress &&pDataDir->Size))
		{
			break;
		}

		pExpDir = (PIMAGE_EXPORT_DIRECTORY)((long)Module + pDataDir->VirtualAddress);

		if( ! pExpDir->Name)
		{
			break;
		}

		if( pExpDir->Name >= pNtHead->OptionalHeader.SizeOfImage)
		{
			break;
		}
		if (!pExpDir->AddressOfNames)
		{
			break;
		}
		if(pExpDir ->AddressOfNames >= pNtHead->OptionalHeader.SizeOfImage) 
		{
			break;
		}
		// �������Rva��ַ��
		FuncNameRva = (long*)(pExpDir->AddressOfNames + (long) Module);

		if( !ExeProbeForRead(FuncNameRva ,sizeof(long) * pExpDir->NumberOfNames))
		{

			break;
		}

		i = 0;
		TempFuncName = NULL;
		//������ż���
		while( i < pExpDir->NumberOfNames)
		{
			//�������������ַ
			TempFuncName = (char*)((ULONG)Module + FuncNameRva[i]);
			//�жϺ����Ƿ�ɶ�
			if( ! ExeProbeForRead(TempFuncName , NameLen + 1))
			{
				TempFuncName = NULL;
				break;
			}

			// �ȽϺ�����������
			if( StrCmp(name , TempFuncName , NameLen + 1 ))
			{
				break;
			}
			TempFuncName = NULL;
			i ++;
		}// end while

		if( NULL ==TempFuncName)
		{
			break;
		}
		if(!pExpDir->AddressOfNameOrdinals)
		{
			break;
		}

		if(pExpDir->AddressOfNameOrdinals >= pNtHead->OptionalHeader.SizeOfImage)
		{
			break;
		}
		// ���㺯�����
		//�����������ַ
		pFuncOld = (PUSHORT)((ULONG)Module + pExpDir->AddressOfNameOrdinals);

		//�ж��ڴ��ַ�Ŀɶ���
		if(!ExeProbeForRead(pFuncOld,sizeof(short)*(i+1)))
		{
			break;
		}

		if(!pExpDir->AddressOfFunctions)
		{
			break;
		}

		if(pExpDir->AddressOfFunctions >= pNtHead->OptionalHeader.SizeOfImage)
		{
			break;
		}


		pFuncRva = (long*)((ULONG)Module + pExpDir->AddressOfFunctions);
		//�ж��ڴ��ַ�Ŀɶ���
		if(!ExeProbeForRead(pFuncRva,sizeof(long)*(pFuncOld[i]+1)))
		{
			break;
		}

		if(pFuncRva[pFuncOld[i]] >= pNtHead->OptionalHeader.SizeOfImage)
		{
			break;
		}
		//�����һ��ת��������������ʱ����ȡ�ú�����ַ
		/*	if(pFuncRva[pFuncOld[i]] >= pExpDir->)
		{
			if(pFuncRva[pFuncOld[i]] < (pExpDir->VirtualAddress + pExpDir->Size))
			{
				//��һ��ת������,������ʱ����ȡ�ú�����ַ
				break;
			}
		}*/

		ret =(void*)(pFuncRva[pFuncOld[i]] + (long)Module);
		break;
} while (0);

return ret;
}



// ģ�����Ƚ�

long __stdcall CmpModuleNameExe(PIMAGE_DOS_HEADER Module,char* pModuleName)
{
	long   Outd;
	char   *ModuleName;
	long   ModuleNameLen;

	PIMAGE_NT_HEADERS        NtHeader;
	PIMAGE_DATA_DIRECTORY    pDataDirectory;
	PIMAGE_EXPORT_DIRECTORY  Export;
	do
	{
		Outd = 0;
		ModuleNameLen = StrLen(pModuleName);
		if(0 == ModuleNameLen)
		{
			break;
		}
		//��λpe��ǩ
		NtHeader=(PIMAGE_NT_HEADERS)((long)Module + Module->e_lfanew);
		//
		pDataDirectory = &NtHeader->OptionalHeader.DataDirectory[0];

		//�Ƿ��������
		if(!(pDataDirectory->VirtualAddress && pDataDirectory->Size))
		{
			break;
		}

		Export=(PIMAGE_EXPORT_DIRECTORY)((ULONG)Module + pDataDirectory->VirtualAddress);
		if(!Export->Name)
		{
			break;
		}
		if(Export->AddressOfNames >= NtHeader->OptionalHeader.SizeOfImage)
		{
			break;
		}
		ModuleName = (char*)((ULONG)Module + Export->Name);
		if(!ExeProbeForRead((PVOID)ModuleName,ModuleNameLen + 1))
		{
			break;
		}
		Outd = StrCmp(ModuleName,pModuleName,ModuleNameLen + 1);
		break;
	}while(0);
	return Outd;
}

// ���ڴ�������ָ��ģ���ģ���ַ

PIMAGE_DOS_HEADER __stdcall FromNameFindModule(char* name)
{
	PIMAGE_DOS_HEADER Module;
	long Temp;
	if( (!name) || '\0' == (*name))
	{

		return NULL;
	}
	Temp = 0x7FFF0000;

	//ѭ�������ڴ�
	while( Temp  >= 0x10000)
	{

		//ȷ���ڴ���Ч

		if( !ExeProbeForRead((PVOID)Temp , 0x10) )
		{
			Temp -= 0x1000;
			continue;
		}

		Module = (PIMAGE_DOS_HEADER) Temp;
		//ȷ��PE ӳ�����ַ

		if( ISPEFILE != TestPEImageExe(Module,0))
		{
			Temp -= 0x1000;
			continue;
		}

		//�Ƚ���һ��ģ��
		if(CmpModuleNameExe(Module , name))
		{
			return Module;
		}
		Temp -= 0x1000;
		continue;
	}
	return NULL;
}
// 
// ��ȡPE��Ϣ

void __stdcall GetNewPEInf(PIMAGE_DOS_HEADER Module ,OUT PNEWPEINF pNewPeInf)
{

	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	long i ;

	if( (!pNewPeInf) || (!Module))
		return ;

	NtHeader = (PIMAGE_NT_HEADERS)((ULONG)Module + Module->e_lfanew);
	i = NtHeader->OptionalHeader.NumberOfRvaAndSizes;			// ����Ŀ¼����
	i = (long)&(NtHeader->OptionalHeader.DataDirectory[i]);
	pSectionHeader = (PIMAGE_SECTION_HEADER)i;


	pNewPeInf->e_lfanew = Module->e_lfanew;//1.��λPE��ǩ��ַ
	pNewPeInf->NumberOfSections = NtHeader->FileHeader.NumberOfSections;//2.PE�ڼ���
	pNewPeInf->SizeOfOptionHeader = NtHeader->FileHeader.SizeOfOptionalHeader;//3.PE��չͷ��С
	pNewPeInf->AddressOfEntryPoint = NtHeader->OptionalHeader.AddressOfEntryPoint;//4.������ڣ��ļ������ȱ�ִ�еĴ���ĵ�һ���ֽڵ�RVA
	pNewPeInf->SectionAlign = NtHeader->OptionalHeader.SectionAlignment;//6.�ڴ�ڶ�������
	pNewPeInf->FileAlign = NtHeader->OptionalHeader.FileAlignment;//7.pe�ڵ��ļ�����ֵ
	pNewPeInf->SizeofImage = NtHeader->OptionalHeader.SizeOfImage;//8.PE�ڴ��е�ӳ��ߴ�
	pNewPeInf->SizeofHeaders = NtHeader->OptionalHeader.SizeOfHeaders;//9.PE���н�ͷ�ӽڱ�Ĵ�С
	pNewPeInf->NumberOfDataDirectory = NtHeader->OptionalHeader.NumberOfRvaAndSizes;//10.Ŀ¼����
	for(i=0;i < 16; i++)
	{
		pNewPeInf->DataDirectory[i] = NtHeader->OptionalHeader.DataDirectory[i];//11.Ŀ¼����
	}

	pNewPeInf ->SizeofRawData = 0;				//���� ȫ������ ���ڶ���� ֮��
	for( i=0;i<pNewPeInf->NumberOfSections ;i++)
	{
		if( pSectionHeader[i].PointerToRawData)
		{
			pNewPeInf->SizeofRawData += pSectionHeader[i].SizeOfRawData;
		}

	}
}

// �Ƚ�2 ��PE��Ϣ

long __stdcall CmpNewPEInf(PNEWPEINF NewPEInf1 ,PNEWPEINF NewPEInf2)
{

	char *p1,*p2;
	long i;
	long ret ;
	p1 = (char*)NewPEInf1;
		p2 = (char*)NewPEInf2;
		ret = 1;

		for ( i=0 ;i<sizeof(NewPEInf1) ; i++)
		{
			if( NULL == p1)
			{
				DB(0xE1);
			}
			if(p1[i] != p2[i])
			{

				ret = 0;
				break;
			}
		}
		return ret;
}