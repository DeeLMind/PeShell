//�쳣���� ����ʱ��ַ��ȡ

#include "ShellCode.h"
#pragma  code_seg("Mycode")


//�쳣������

EXCEPTION_DISPOSITION __cdecl Exception_Handler(
	struct _EXCEPTION_RECORD* ExceptionRecode,		//EXCEPTION_RECORD
		void* EstablisherFrame,						//�쳣֡�ṹ
		struct _CONTEXT* ContextRecode,				//�쳣����ʱ ������
		void* DispacherContext
	)
		{
			PCODE_ERROR_ESP ErrorInf = (PCODE_ERROR_ESP)EstablisherFrame;
			// ��ȡ�쳣����
			ErrorInf->inf->ExceptionCode =  ExceptionRecode->ExceptionCode;
			//�ָ�esp
		//	ContextRecode->Esp = (DWORD)EstablisherFrame;   //�ָ�ESP ֵ
			//����Eip
			ContextRecode->Eip = ErrorInf->inf->Eip;			//ָ��ж�غ���
			// ���� �Ѵ����쳣 ����ִ��
			return ExceptionContinueExecution;
		}



		
		
long __stdcall GetRunAddressSubIfAddress ();

		//���� ���е�ַ - �����ַ

//
//
//    ���� RunAddressSubIfAddress ʱ
//  	push ebp 
//  	mov ebp ,esp
//     RetAddress ��: [ esp + 8 ] ʵ��  <��ʵֵ��  �� ���ص� GetRunAddress ����һ����ַ>
//    [ esp+ 4 ] �Ƿ��ص�ַ Ҳ���� GetRunAddress���� RunAddressSubIfAddress �����һ����ַ
//	   pRetAddress = &RetAddress �� Ҳ����  pRetAddress = esp + 8
//	   pRetAddress --  ���� esp + 4  Ҳ����ָ����� ���ص�ַ (����ʱ)
//     ��ô (* pRetAddress )  <�����Ƿ��� GetRunAddressSubIfAddress ��һ����ַ >-  ( GetRunAddressSubIfAddress + 5  �������һ��ָ���ַ) 
//     �����ֵ���� ����ʱ  �� ����ʱ �Ĳ�ֵ���õ������ֵ�Ϳ��� ��λ���� ����ʱ�����ˡ�����
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




// �������ַת��Ϊ����ʱ��ַ

PVOID __stdcall GetRunAddress(PVOID pData)
{

	if( NULL == pData)
	{
		DB(0xE2);
	}
	// ����ֵ + ƫ��(����ʱ - ����ʱ)

	long sub =  GetRunAddressSubIfAddress();
	long ret = (long)((long)pData + sub);
	

/*
	printf(" 0x%x  : ret 0x%x  sub 0x: %x" ,pData,ret , sub);
	getchar();
	getchar();
	getchar();*/
	
	return (PVOID) ret;
}

//�ж�һ���ڴ��Ƿ���Զ�ȡ������0 ʧ��
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
	
	ErrorInf.Eip = (unsigned long)GetRunAddress((PVOID)Temp);		//EIP ָ�� Exception_Handler

	Temp = (long)GetRunAddress((PVOID)Exception_Handler);

	_asm{

		push Temp1		// &ErrorInf.Eip  *ErrorInf.Eip = offset RunText  �����쳣�� �������ὫEIP����Ϊ�����ֵ
		push Temp		// offset RunText
		push dword ptr fs:[0]
		mov fs:[0] ,esp
		mov esi ,Address
		mov ecx ,len
		rep lodsb //���������������� ��ȡ esi��ַ�����ݵ� al �� ecx��
		}

///////////////////�����쳣 ʱ ���� �쳣�������/////////////////////////

RunText:
	_asm{
		pop dword ptr fs:[0]
		pop eax
		pop eax
		popad

		}
	if(-1 == ErrorInf.ExceptionCode)
	{
		// û���쳣
		return 1;
	}
	return 0;


}

