#include "ShellCode.h"

// 提供PE文件操作
#pragma code_seg("Mycode")


#define  ISPEFILE 10

// PE文件基址确定函数

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
			if( 0xFFFF & (ULONG) Module)	//内存没对齐
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
		// nt 头偏移为8的倍数
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
		//不是有效的exe pe文件属性
		if(!((0x100&pNtHead->FileHeader.Characteristics)
			&&(0==(0x3000&pNtHead->FileHeader.Characteristics))))
		{
			//不是dll文件属性
			if(!((0x100&pNtHead->FileHeader.Characteristics)
				&&(0x2000&pNtHead->FileHeader.Characteristics)))
			{
				//不是驱动文件属性
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
							// 映像时不时按照节对齐
		if( pNtHead->OptionalHeader.SizeOfImage 	& (pNtHead->OptionalHeader.SectionAlignment - 1))
		{

			break;
		}


		ret ++;	// ret =10
		break;
	}while (0);
	return ret;
}


//	1比较序号得到 当前序列
//  2按序列值找到 顺序表中的真正下标
//	3带入下表 到导出函数地址表


// 获得一个模块导出的函数地址
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
		//定位PE标签
		pNtHead = (PIMAGE_NT_HEADERS )(Module->e_lfanew + (long)Module);
		pDataDir = pNtHead->OptionalHeader.DataDirectory;

		// 是否有输出表
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
		// 输出符号Rva地址表
		FuncNameRva = (long*)(pExpDir->AddressOfNames + (long) Module);

		if( !ExeProbeForRead(FuncNameRva ,sizeof(long) * pExpDir->NumberOfNames))
		{

			break;
		}

		i = 0;
		TempFuncName = NULL;
		//输出符号计数
		while( i < pExpDir->NumberOfNames)
		{
			//计算输出函数地址
			TempFuncName = (char*)((ULONG)Module + FuncNameRva[i]);
			//判断函数是否可读
			if( ! ExeProbeForRead(TempFuncName , NameLen + 1))
			{
				TempFuncName = NULL;
				break;
			}

			// 比较函数符号名称
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
		// 计算函数序号
		//计算索引表地址
		pFuncOld = (PUSHORT)((ULONG)Module + pExpDir->AddressOfNameOrdinals);

		//判断内存地址的可读性
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
		//判断内存地址的可读性
		if(!ExeProbeForRead(pFuncRva,sizeof(long)*(pFuncOld[i]+1)))
		{
			break;
		}

		if(pFuncRva[pFuncOld[i]] >= pNtHead->OptionalHeader.SizeOfImage)
		{
			break;
		}
		//如果是一个转发函数，这里暂时不获取该函数地址
		/*	if(pFuncRva[pFuncOld[i]] >= pExpDir->)
		{
			if(pFuncRva[pFuncOld[i]] < (pExpDir->VirtualAddress + pExpDir->Size))
			{
				//是一个转发函数,这里暂时不获取该函数地址
				break;
			}
		}*/

		ret =(void*)(pFuncRva[pFuncOld[i]] + (long)Module);
		break;
} while (0);

return ret;
}



// 模块名比较

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
		//定位pe标签
		NtHeader=(PIMAGE_NT_HEADERS)((long)Module + Module->e_lfanew);
		//
		pDataDirectory = &NtHeader->OptionalHeader.DataDirectory[0];

		//是否有输出表
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

// 在内存中搜索指定模块的模块基址

PIMAGE_DOS_HEADER __stdcall FromNameFindModule(char* name)
{
	PIMAGE_DOS_HEADER Module;
	long Temp;
	if( (!name) || '\0' == (*name))
	{

		return NULL;
	}
	Temp = 0x7FFF0000;

	//循环搜索内存
	while( Temp  >= 0x10000)
	{

		//确定内存有效

		if( !ExeProbeForRead((PVOID)Temp , 0x10) )
		{
			Temp -= 0x1000;
			continue;
		}

		Module = (PIMAGE_DOS_HEADER) Temp;
		//确定PE 映像基地址

		if( ISPEFILE != TestPEImageExe(Module,0))
		{
			Temp -= 0x1000;
			continue;
		}

		//比较下一个模块
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
// 获取PE信息

void __stdcall GetNewPEInf(PIMAGE_DOS_HEADER Module ,OUT PNEWPEINF pNewPeInf)
{

	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	long i ;

	if( (!pNewPeInf) || (!Module))
		return ;

	NtHeader = (PIMAGE_NT_HEADERS)((ULONG)Module + Module->e_lfanew);
	i = NtHeader->OptionalHeader.NumberOfRvaAndSizes;			// 数据目录项数
	i = (long)&(NtHeader->OptionalHeader.DataDirectory[i]);
	pSectionHeader = (PIMAGE_SECTION_HEADER)i;


	pNewPeInf->e_lfanew = Module->e_lfanew;//1.定位PE标签地址
	pNewPeInf->NumberOfSections = NtHeader->FileHeader.NumberOfSections;//2.PE节计数
	pNewPeInf->SizeOfOptionHeader = NtHeader->FileHeader.SizeOfOptionalHeader;//3.PE扩展头大小
	pNewPeInf->AddressOfEntryPoint = NtHeader->OptionalHeader.AddressOfEntryPoint;//4.程序入口，文件中首先被执行的代码的第一个字节的RVA
	pNewPeInf->SectionAlign = NtHeader->OptionalHeader.SectionAlignment;//6.内存节对齐粒度
	pNewPeInf->FileAlign = NtHeader->OptionalHeader.FileAlignment;//7.pe节的文件对齐值
	pNewPeInf->SizeofImage = NtHeader->OptionalHeader.SizeOfImage;//8.PE内存中的映像尺寸
	pNewPeInf->SizeofHeaders = NtHeader->OptionalHeader.SizeOfHeaders;//9.PE所有节头加节表的大小
	pNewPeInf->NumberOfDataDirectory = NtHeader->OptionalHeader.NumberOfRvaAndSizes;//10.目录计数
	for(i=0;i < 16; i++)
	{
		pNewPeInf->DataDirectory[i] = NtHeader->OptionalHeader.DataDirectory[i];//11.目录数据
	}

	pNewPeInf ->SizeofRawData = 0;				//等于 全部节区 按节对其后 之和
	for( i=0;i<pNewPeInf->NumberOfSections ;i++)
	{
		if( pSectionHeader[i].PointerToRawData)
		{
			pNewPeInf->SizeofRawData += pSectionHeader[i].SizeOfRawData;
		}

	}
}

// 比较2 个PE信息

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