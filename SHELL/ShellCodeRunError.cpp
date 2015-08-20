//异常处理 运行时地址获取

#include "ShellCode.h"
#pragma  code_seg("Mycode")


//异常处理函数

EXCEPTION_DISPOSITION __cdecl Exception_Handler(
	struct _EXCEPTION_RECORD* ExceptionRecode,		//EXCEPTION_RECORD
		void* EstablisherFrame,						//异常帧结构
		struct _CONTEXT* ContextRecode,				//异常发生时 上下文
		void* DispacherContext
	)
		{
			PCODE_ERROR_ESP ErrorInf = (PCODE_ERROR_ESP)EstablisherFrame;
			// 获取异常，码
			ErrorInf->inf->ExceptionCode =  ExceptionRecode->ExceptionCode;
			//恢复esp
		//	ContextRecode->Esp = (DWORD)EstablisherFrame;   //恢复ESP 值
			//设置Eip
			ContextRecode->Eip = ErrorInf->inf->Eip;			//指向卸载函数
			// 设置 已处理异常 继续执行
			return ExceptionContinueExecution;
		}



		
		
long __stdcall GetRunAddressSubIfAddress ();

		//计算 运行地址 - 编译地址

//
//
//    跳到 RunAddressSubIfAddress 时
//  	push ebp 
//  	mov ebp ,esp
//     RetAddress 在: [ esp + 8 ] 实参  <其实值是  的 返回到 GetRunAddress 的下一条地址>
//    [ esp+ 4 ] 是返回地址 也就是 GetRunAddress调用 RunAddressSubIfAddress 后的下一条地址
//	   pRetAddress = &RetAddress ， 也就是  pRetAddress = esp + 8
//	   pRetAddress --  就是 esp + 4  也就是指向的是 返回地址 (运行时)
//     那么 (* pRetAddress )  <运行是返回 GetRunAddressSubIfAddress 下一条地址 >-  ( GetRunAddressSubIfAddress + 5  编译后下一条指令地址) 
//     这个差值就是 运行时  与 编译时 的差值，得到这个差值就可以 定位所有 编译时数据了。。。
//


long __stdcall RunAddressSubIfAddress(long RetAddress)
		{
			long* pRetAddress;
			long ret ;

			if(0 == RetAddress)
			{
				DB(0xCC);
				DB(0xEB);
				DB(0xCC);
			}
			pRetAddress = &RetAddress;
			pRetAddress --;

			ret = (*pRetAddress) - 5 - (long)GetRunAddressSubIfAddress;
	
		*pRetAddress = RetAddress;
		
		return ret;
		}

__declspec(naked)

long __stdcall GetRunAddressSubIfAddress()
{
	__asm call RunAddressSubIfAddress;
}




// 将编译地址转换为运行时地址

PVOID __stdcall GetRunAddress(PVOID pData)
{

	if( NULL == pData)
	{
		DB(0xE2);
	}
	// 编译值 + 偏移(运行时 - 编译时)

	long sub =  GetRunAddressSubIfAddress();
	long ret = (long)((long)pData + sub);
	

/*
	printf(" 0x%x  : ret 0x%x  sub 0x: %x" ,pData,ret , sub);
	getchar();
	getchar();
	getchar();*/
	
	return (PVOID) ret;
}

//判断一段内存是否可以读取，返回0 失败
long __stdcall ExeProbeForRead(PVOID Address , long len)
{


	CODE_ERROR_RUN_INF ErrorInf = {0};
	long Temp ,Temp1;
	ErrorInf.ExceptionCode = -1 ;

	Temp1 = (DWORD)&ErrorInf.Eip;
	_asm{
		pushad;
		mov eax ,offset RunText
		mov Temp ,eax
		}
	
	ErrorInf.Eip = (unsigned long)GetRunAddress((PVOID)Temp);		//EIP 指向 Exception_Handler

	Temp = (long)GetRunAddress((PVOID)Exception_Handler);

	_asm{

		push Temp1		// &ErrorInf.Eip  *ErrorInf.Eip = offset RunText  发生异常后 处理程序会将EIP设置为这个数值
		push Temp		// offset RunText
		push dword ptr fs:[0]
		mov fs:[0] ,esp
		mov esi ,Address
		mov ecx ,len
		rep lodsb //程序可能在这里出错 读取 esi地址处数据到 al 中 ecx次
		}

///////////////////发生异常 时 跳入 异常处理程序/////////////////////////

RunText:
	_asm{
		pop dword ptr fs:[0]
		pop eax
		pop eax
		popad

		}
	if(-1 == ErrorInf.ExceptionCode)
	{
		// 没有异常
		return 1;
	}
	return 0;


}

