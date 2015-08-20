// �ṩ�ǳ��� ����ʱ ���õĺ���s
#include "ShellCode.h"


//���³��� �����Mycode��
#pragma  code_seg("Mycode")


//�ַ������ȼ���

long __stdcall StrLen(char* str)
{
	long out = 0;

	if(NULL == str)
		return out;

	while(*str)
	{
		out++;
		str++;
	}
	return out;
}

// ���Ϊ1
long __stdcall StrCmp (char* str1 ,char* str2 ,long MAX)
{
	long i ;

	if( *str1 == '\0' || *str2 == '\0')
		return 0;

	for( i =0 ;i<MAX ; i++)
	{
		if( str1[i] != str2[i] )
			break;
	}

	return ( i >= MAX  )? 1 : 0;

}
// ��ȡ�ǳ���ʹ�õ����ݵ�ַ

void __stdcall GetExeShellCodeData( OUT PSHELLCODEINF*		 pShellCodeInf,
									OUT PSHELLWINDOWSINF*    pShellWindowsInf,
									OUT PKERNEL32_API*		 pKernel32_API,
									OUT PUSER32_API*		 pUser32_API)
{	

	

	//
	//	ʹ��ʱ����ת��Ϊ����ʱ��ַ
	//
	if( NULL != pShellCodeInf)
	{
		(*pShellCodeInf) = (PSHELLCODEINF)GetRunAddress(&ShellDataInf);
	}
	if( NULL != pShellWindowsInf)
	{
		(*pShellWindowsInf) = (PSHELLWINDOWSINF)GetRunAddress((PSHELLWINDOWSINF)ExeWindowsInf);
	}
	if( NULL != pKernel32_API)
	{
		(*pKernel32_API) = (PKERNEL32_API)GetRunAddress(&KerApi);
	}
	if( NULL != pUser32_API)
	{
		(*pUser32_API) = (PUSER32_API)GetRunAddress(&UserApi);
	}
}

//��KerAPI �� UserApi ���г�ʼ��

#pragma  data_seg("Mydata")

long __stdcall InlineApiAddress()
{
	PKERNEL32_API pKerApi;
	PUSER32_API pUserApi;

	PIMAGE_DOS_HEADER KerModule, UserModule;

	PT_GetProcAddress pGetProAddress;
	char* pModuleName;
	long i ;

	//��ȡ�ǳ���ʹ�õ����ݵ�ַ

	GetExeShellCodeData(NULL,NULL,&pKerApi,&pUserApi);

	//���ݱ���� Mydata��


	// ������Ҫ�ĺ���API����
	// �����ض�λ���⣬ֱ��ʹ��Ӳ�����ַ�����ַ�ᵼ��ʧ��
	// ������� GetRunAddress ����̬��ȡ�ַ�����ַ
	//

	pKerApi->pcGetProcAddress		 = (char*)GetRunAddress("GetProcAddress");
	pKerApi->pcLoadLibraryA			= (char*)GetRunAddress("LoadLibraryA");
	pKerApi->pcGetModuleHandleA		= (char*)GetRunAddress("GetModuleHandleA");
	pKerApi->pcExitProcess			 = (char*)GetRunAddress("ExitProcess");
	pUserApi->pcRegisterClassExA	 = (char*)GetRunAddress("RegisterClassExA");
	pUserApi->pcCreateWindowExA		 = (char*)GetRunAddress("CreateWindowExA");
	pUserApi->pcShowWindow			= (char*)GetRunAddress("ShowWindow");
	pUserApi->pcUpdateWindow          = (char*)GetRunAddress("UpdateWindow");
	pUserApi->pcGetMessageA           = (char*)GetRunAddress("GetMessageA");
	pUserApi->pcTranslateAccelerator  = (char*)GetRunAddress("TranslateAccelerator");	
	pUserApi->pcTranslateMessage	= (char*)GetRunAddress("TranslateMessage");
	pUserApi->pcDispatchMessageA	= (char*)GetRunAddress("DispatchMessageA");
	pUserApi->pcGetDlgItemTextA		 = (char*)GetRunAddress("GetDlgItemTextA");
	pUserApi->pcDefWindowProcA		 = (char*)GetRunAddress("DefWindowProcA");
	pUserApi->pcPostQuitMessage		 = (char*)GetRunAddress("PostQuitMessage");
	pUserApi->pcDestroyWindow		 = (char*)GetRunAddress("DestroyWindow");
	pUserApi->pcMessageBoxA			 = (char*)GetRunAddress("MessageBoxA");
	pModuleName = (char*)GetRunAddress("KERNEL32.dll");

	// ��ȡ Kernel32.dll ģ�����ַ
	KerModule = FromNameFindModule(pModuleName);
	if( NULL == KerModule)
	{
		return 0;
	}
	//�� ����ģ���ȡ ��������API ������ʱ��ַ 

	pGetProAddress = (PT_GetProcAddress)GetProceAddressExe(KerModule ,pKerApi->pcGetProcAddress);
	if( NULL == pGetProAddress)
	{
		return 0;
	}

	//��ȡ  KerAPI ���� API ��ַ
	for ( i = 0 ; i< ( sizeof(*pKerApi) / sizeof(char*)); i++)
	{
		pModuleName = ((char**)pKerApi)[i];	//��ȡ�ṹ���к�������
		((char**)pKerApi)[i] = (char*)pGetProAddress(KerModule ,pModuleName);
		if( NULL == ((char**)pKerApi)[i] ) return 0;
	}
	pModuleName = (char*) GetRunAddress( "USER32.DLL");
	// ��ȡ user32.dll ģ�飬�Լ��صķ�ʽ��ȡ
	UserModule = (PIMAGE_DOS_HEADER)pKerApi->LoadLibraryA(pModuleName);
	if( NULL == UserModule)
	{
		return 0;
	}
	//��ȡ User32 �ṹ�� APi ����ʱ��ַ
	for ( i=0 ; i< ((sizeof(*pUserApi) / sizeof(char*))); i++)
	{
		pModuleName = ((char**)pUserApi)[i];
		((char**)pUserApi)[i] = (char*)pGetProAddress(UserModule ,pModuleName);
		if( 	NULL == ((char**)pUserApi)[i] )
			return 0;
	}

	return 1;
}



//���� �ǳ��򴰿ڵ� ���пؼ�
#pragma  data_seg("Mydata")
void __stdcall ExeShellCodeCreateWindows(HWND hWnd , HINSTANCE hInstance)
{
	PKERNEL32_API pkerApi;
	PUSER32_API	pUserApi;
	PSHELLWINDOWSINF pExeWindowsInf;


	char* pSzClassName   = (char*)GetRunAddress("Shell Show");
	char* pSzButtonClass = (char*)GetRunAddress("button");
	char* pSzEditClass   = (char*)GetRunAddress("edit");
	char* pSzLabelClass  = (char*)GetRunAddress("static");
//	char* pSzLabel1      = (char*)GetRunAddress("QQ: ");
	char* pSzLabel2      = (char*)GetRunAddress("PASS");
	char* pSzButtonText1 = (char*)GetRunAddress("��  ֤");
	char* pSzButtonText2 = (char*)GetRunAddress("ȡ  ��");

	// ��ȡ����ʱ ���ݵ�ַ
	GetExeShellCodeData(NULL , &pExeWindowsInf ,&pkerApi ,&pUserApi);

	pExeWindowsInf[0].Id=(HMENU)0;
//	pExeWindowsInf[1].Id=(HMENU)1;
	pExeWindowsInf[2].Id=(HMENU)2;
	pExeWindowsInf[3].Id=(HMENU)3;
	pExeWindowsInf[4].Id=(HMENU)4;
	pExeWindowsInf[5].Id=(HMENU)5;
	pExeWindowsInf[6].Id=(HMENU)6;


	//������̬�ı���
//	pExeWindowsInf[1].hWnd = pUserApi->CreateWindowExA
//		(0,pSzLabelClass,pSzLabel1,WS_CHILD|WS_VISIBLE
//		,25,20,80,20,hWnd,(HMENU)1,hInstance,NULL);

	//������̬�ı���
	pExeWindowsInf[2].hWnd = pUserApi->CreateWindowExA
		(0,pSzLabelClass,pSzLabel2,WS_CHILD|WS_VISIBLE
		,25,50,80,20,hWnd,(HMENU)2,hInstance,NULL);

	//�����������û������ı���
//	pExeWindowsInf[3].hWnd = pUserApi->CreateWindowExA
//		(WS_EX_TOPMOST,pSzEditClass,NULL,WS_CHILD|WS_VISIBLE
//		|WS_BORDER,105,19,170,22,hWnd,(HMENU)3,hInstance,NULL);

	//����������������ı���
	pExeWindowsInf[4].hWnd = pUserApi->CreateWindowExA
		(WS_EX_TOPMOST,pSzEditClass,NULL,WS_CHILD|WS_VISIBLE
		|WS_BORDER|ES_PASSWORD,105,49,170,22,hWnd,(HMENU)4
		,hInstance,NULL);

	//������½��ť
	pExeWindowsInf[5].hWnd = pUserApi->CreateWindowExA
		(NULL,pSzButtonClass,pSzButtonText1,WS_CHILD|WS_VISIBLE
		,60,100,60,30,hWnd,(HMENU)5,hInstance,NULL);

	//����ȡ����ť
	pExeWindowsInf[6].hWnd = pUserApi->CreateWindowExA
		(NULL,pSzButtonClass,pSzButtonText2,WS_CHILD|WS_VISIBLE
		,180,100,60,30,hWnd,(HMENU)6,hInstance,NULL);
}

// �ǳ��򴰿ڴ�����
#pragma  data_seg("Mydata")
LRESULT __stdcall ExeShellCodeWndProc(HWND hWnd,UINT message,WPARAM wParam,LPARAM lParam)
{
	HINSTANCE         hInstance;
	PSHELLCODEINF     pShellDataInf;
	PKERNEL32_API	  pKerApi;
	PUSER32_API       pUserApi;
	PSHELLWINDOWSINF  pExeWindowsInf;
	char	pass[10] = { 0 };
	//��ȡ�ǳ���ʹ�õ����ݵ�ַ
	GetExeShellCodeData(&pShellDataInf,&pExeWindowsInf,&pKerApi,&pUserApi);
	
	//��ȡ����ģ�����ַ
	hInstance=pShellDataInf->Hinstance;
		
	switch(message)
	{
	case WM_CREATE://�������ڱ�����
		{
			if(NULL == hInstance)
			{
				return -1;
			}
			//�����ǳ��򴰿ڵ����пؼ�
			ExeShellCodeCreateWindows(hWnd,hInstance);
			break;
		}
	case WM_COMMAND://����˵������ټ���Ϣ
		{
			//��½��ť������Ͳ��Ե�¼��Ϣ�����κβ�����
			if((5 == (0xFF & wParam)) && (hWnd == pExeWindowsInf[0].hWnd))
			{

				pUserApi->GetDlgItemTextA(pExeWindowsInf[0].hWnd,(int)pExeWindowsInf[4].Id,
					pass , 10);
			/*	pUserApi->MessageBoxA(0,0,pass,0);*/
				if( StrCmp(pass,(char*)GetRunAddress("123444") , 6) )
				{
					pExeWindowsInf[0].Id=(HMENU)1;
				}

				else 
					pExeWindowsInf[0].Id=(HMENU)0;

				
				pUserApi->DestroyWindow(pExeWindowsInf[0].hWnd);
				pUserApi->PostQuitMessage(0);
			}
			//ȡ����ť
			else if(6 == (0xFF & wParam))
			{
				pExeWindowsInf[0].Id=(HMENU)0;
				pKerApi->ExitProcess(0);
			}
			break;
		}
	case WM_CLOSE:// �û�Ҫ��رմ���
		{
			pExeWindowsInf[0].Id=(HMENU)0;
			pKerApi->ExitProcess(0);
			break;
		}
	default:
		{
			return pUserApi->DefWindowProcA(hWnd,message,wParam,lParam);
		}
	}
	return pUserApi->DefWindowProcA(hWnd,message,wParam,lParam);
}

//show Windows
#pragma data_seg("Mydata")
long __stdcall ExeShellCodeShowWindows()
{

	HWND hWnd;
	HINSTANCE         hInstance;
	WNDPROC           pWndProc;
	WNDCLASSEXA       wcex={0};
	
	PSHELLCODEINF     pShellDataInf;
	PKERNEL32_API	  pKerApi;
	PUSER32_API       pUserApi;
	PSHELLWINDOWSINF  pExeWindowsInf;
	
	//�������ݱ����ExeData��

	char* szWindowClass=(char*)GetRunAddress("Login");
	char* szCaptionMain=(char*)GetRunAddress("ϵͳ��¼");
	
	//��λϵͳ��¼�Ի��򴰿���Ϣ��������ַ
	pWndProc = (WNDPROC)GetRunAddress(ExeShellCodeWndProc);
	
	//��ȡ�ǳ���ʹ�õ����ݵ�ַ
	GetExeShellCodeData(&pShellDataInf,&pExeWindowsInf,&pKerApi,&pUserApi);
	
	//��ȡ����ģ�����ַ
	hInstance = pShellDataInf->Hinstance;
	
	//
	wcex.hInstance=hInstance;
	wcex.cbSize=sizeof(WNDCLASSEX);
	wcex.style=CS_HREDRAW|CS_VREDRAW;
	wcex.lpfnWndProc=pWndProc;
	wcex.hbrBackground=(HBRUSH)(COLOR_WINDOW);
	wcex.lpszClassName=szWindowClass;
	pUserApi->RegisterClassExA(&wcex);
	
	//�������߳�������
	hWnd = pUserApi->CreateWindowExA( 
		WS_EX_CLIENTEDGE,// ��չ��ʽ
		szWindowClass,//����	
		szCaptionMain,//����
		WS_OVERLAPPED|WS_CAPTION|WS_MINIMIZEBOX,// ������ʽ
		300,	// ��ʼ X ����
		200,	// ��ʼ y ����
		300,	// ���
		180,	// �߶�
		NULL,	// �����ھ��
		NULL,	// �˵����
		hInstance,// ����ʵ�����
		NULL);
	
	if(NULL==hWnd)
	{
		return 0;
	}
	
	pExeWindowsInf[0].hWnd=hWnd;
	pExeWindowsInf[0].Id=NULL;
	
	pUserApi->ShowWindow(hWnd,SW_SHOWNORMAL);
	pUserApi->UpdateWindow(hWnd);
	//������Ϣѭ��
	MSG msg;
	while(pUserApi->GetMessageA(&msg,NULL,0,0))
	{
		if(NULL == pUserApi)
		{
			DB(0xC2);
		}
		pUserApi->TranslateMessage(&msg);
		pUserApi->DispatchMessageA(&msg);
	}
	
	char * pText0,*pText1;
	if((long)pExeWindowsInf[0].Id)		//0��id = 1 �Ļ� ��֤�ɹ�
	{
		pText0 = (char*)GetRunAddress("��ӭ��¼");
		pText1 = (char*)GetRunAddress("��½");
		
		if(NULL == pText1)
		{
			DB(0xB8);
		}
		pUserApi->MessageBoxA(0,pText0,pText1,0);
	}
	return (long)pExeWindowsInf[0].Id;
}


void ExeShellCodeShowWIndowsEnd()
{


};