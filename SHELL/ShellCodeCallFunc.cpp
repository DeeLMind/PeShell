// 提供壳程序 运行时 调用的函数s
#include "ShellCode.h"


//以下程序 编译进Mycode节
#pragma  code_seg("Mycode")


//字符串长度计算

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

// 相等为1
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
// 获取壳程序使用的数据地址

void __stdcall GetExeShellCodeData( OUT PSHELLCODEINF*		 pShellCodeInf,
									OUT PSHELLWINDOWSINF*    pShellWindowsInf,
									OUT PKERNEL32_API*		 pKernel32_API,
									OUT PUSER32_API*		 pUser32_API)
{	

	

	//
	//	使用时必须转换为运行时地址
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

//对KerAPI 和 UserApi 进行初始化

#pragma  data_seg("Mydata")

long __stdcall InlineApiAddress()
{
	PKERNEL32_API pKerApi;
	PUSER32_API pUserApi;

	PIMAGE_DOS_HEADER KerModule, UserModule;

	PT_GetProcAddress pGetProAddress;
	char* pModuleName;
	long i ;

	//获取壳程序使用的数据地址

	GetExeShellCodeData(NULL,NULL,&pKerApi,&pUserApi);

	//数据编译进 Mydata节


	// 设置需要的函数API名称
	// 由于重定位问题，直接使用硬编码字符串地址会导致失败
	// 这里调用 GetRunAddress 来动态获取字符串地址
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

	// 获取 Kernel32.dll 模块基地址
	KerModule = FromNameFindModule(pModuleName);
	if( NULL == KerModule)
	{
		return 0;
	}
	//从 给定模块获取 给定名称API 的运行时地址 

	pGetProAddress = (PT_GetProcAddress)GetProceAddressExe(KerModule ,pKerApi->pcGetProcAddress);
	if( NULL == pGetProAddress)
	{
		return 0;
	}

	//获取  KerAPI 所用 API 地址
	for ( i = 0 ; i< ( sizeof(*pKerApi) / sizeof(char*)); i++)
	{
		pModuleName = ((char**)pKerApi)[i];	//获取结构体中函数名称
		((char**)pKerApi)[i] = (char*)pGetProAddress(KerModule ,pModuleName);
		if( NULL == ((char**)pKerApi)[i] ) return 0;
	}
	pModuleName = (char*) GetRunAddress( "USER32.DLL");
	// 获取 user32.dll 模块，以加载的方式获取
	UserModule = (PIMAGE_DOS_HEADER)pKerApi->LoadLibraryA(pModuleName);
	if( NULL == UserModule)
	{
		return 0;
	}
	//获取 User32 结构中 APi 运行时地址
	for ( i=0 ; i< ((sizeof(*pUserApi) / sizeof(char*))); i++)
	{
		pModuleName = ((char**)pUserApi)[i];
		((char**)pUserApi)[i] = (char*)pGetProAddress(UserModule ,pModuleName);
		if( 	NULL == ((char**)pUserApi)[i] )
			return 0;
	}

	return 1;
}



//创建 壳程序窗口的 所有控件
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
	char* pSzButtonText1 = (char*)GetRunAddress("认  证");
	char* pSzButtonText2 = (char*)GetRunAddress("取  消");

	// 获取运行时 数据地址
	GetExeShellCodeData(NULL , &pExeWindowsInf ,&pkerApi ,&pUserApi);

	pExeWindowsInf[0].Id=(HMENU)0;
//	pExeWindowsInf[1].Id=(HMENU)1;
	pExeWindowsInf[2].Id=(HMENU)2;
	pExeWindowsInf[3].Id=(HMENU)3;
	pExeWindowsInf[4].Id=(HMENU)4;
	pExeWindowsInf[5].Id=(HMENU)5;
	pExeWindowsInf[6].Id=(HMENU)6;


	//创建静态文本框
//	pExeWindowsInf[1].hWnd = pUserApi->CreateWindowExA
//		(0,pSzLabelClass,pSzLabel1,WS_CHILD|WS_VISIBLE
//		,25,20,80,20,hWnd,(HMENU)1,hInstance,NULL);

	//创建静态文本框
	pExeWindowsInf[2].hWnd = pUserApi->CreateWindowExA
		(0,pSzLabelClass,pSzLabel2,WS_CHILD|WS_VISIBLE
		,25,50,80,20,hWnd,(HMENU)2,hInstance,NULL);

	//创建可输入用户名的文本框
//	pExeWindowsInf[3].hWnd = pUserApi->CreateWindowExA
//		(WS_EX_TOPMOST,pSzEditClass,NULL,WS_CHILD|WS_VISIBLE
//		|WS_BORDER,105,19,170,22,hWnd,(HMENU)3,hInstance,NULL);

	//创建可输入密码的文本框
	pExeWindowsInf[4].hWnd = pUserApi->CreateWindowExA
		(WS_EX_TOPMOST,pSzEditClass,NULL,WS_CHILD|WS_VISIBLE
		|WS_BORDER|ES_PASSWORD,105,49,170,22,hWnd,(HMENU)4
		,hInstance,NULL);

	//创建登陆按钮
	pExeWindowsInf[5].hWnd = pUserApi->CreateWindowExA
		(NULL,pSzButtonClass,pSzButtonText1,WS_CHILD|WS_VISIBLE
		,60,100,60,30,hWnd,(HMENU)5,hInstance,NULL);

	//创建取消按钮
	pExeWindowsInf[6].hWnd = pUserApi->CreateWindowExA
		(NULL,pSzButtonClass,pSzButtonText2,WS_CHILD|WS_VISIBLE
		,180,100,60,30,hWnd,(HMENU)6,hInstance,NULL);
}

// 壳程序窗口处理函数
#pragma  data_seg("Mydata")
LRESULT __stdcall ExeShellCodeWndProc(HWND hWnd,UINT message,WPARAM wParam,LPARAM lParam)
{
	HINSTANCE         hInstance;
	PSHELLCODEINF     pShellDataInf;
	PKERNEL32_API	  pKerApi;
	PUSER32_API       pUserApi;
	PSHELLWINDOWSINF  pExeWindowsInf;
	char	pass[10] = { 0 };
	//获取壳程序使用的数据地址
	GetExeShellCodeData(&pShellDataInf,&pExeWindowsInf,&pKerApi,&pUserApi);
	
	//获取本地模块基地址
	hInstance=pShellDataInf->Hinstance;
		
	switch(message)
	{
	case WM_CREATE://窗口正在被创建
		{
			if(NULL == hInstance)
			{
				return -1;
			}
			//创建壳程序窗口的所有控件
			ExeShellCodeCreateWindows(hWnd,hInstance);
			break;
		}
	case WM_COMMAND://处理菜单及加速键消息
		{
			//登陆按钮，这里就不对登录信息进行任何操作了
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
			//取消按钮
			else if(6 == (0xFF & wParam))
			{
				pExeWindowsInf[0].Id=(HMENU)0;
				pKerApi->ExitProcess(0);
			}
			break;
		}
	case WM_CLOSE:// 用户要求关闭窗口
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
	
	//以下数据编译进ExeData节

	char* szWindowClass=(char*)GetRunAddress("Login");
	char* szCaptionMain=(char*)GetRunAddress("系统登录");
	
	//定位系统登录对话框窗口消息处理函数地址
	pWndProc = (WNDPROC)GetRunAddress(ExeShellCodeWndProc);
	
	//获取壳程序使用的数据地址
	GetExeShellCodeData(&pShellDataInf,&pExeWindowsInf,&pKerApi,&pUserApi);
	
	//获取本地模块基地址
	hInstance = pShellDataInf->Hinstance;
	
	//
	wcex.hInstance=hInstance;
	wcex.cbSize=sizeof(WNDCLASSEX);
	wcex.style=CS_HREDRAW|CS_VREDRAW;
	wcex.lpfnWndProc=pWndProc;
	wcex.hbrBackground=(HBRUSH)(COLOR_WINDOW);
	wcex.lpszClassName=szWindowClass;
	pUserApi->RegisterClassExA(&wcex);
	
	//创建并线程主窗口
	hWnd = pUserApi->CreateWindowExA( 
		WS_EX_CLIENTEDGE,// 扩展样式
		szWindowClass,//类名	
		szCaptionMain,//标题
		WS_OVERLAPPED|WS_CAPTION|WS_MINIMIZEBOX,// 窗口样式
		300,	// 初始 X 坐标
		200,	// 初始 y 坐标
		300,	// 宽度
		180,	// 高度
		NULL,	// 父窗口句柄
		NULL,	// 菜单句柄
		hInstance,// 程序实例句柄
		NULL);
	
	if(NULL==hWnd)
	{
		return 0;
	}
	
	pExeWindowsInf[0].hWnd=hWnd;
	pExeWindowsInf[0].Id=NULL;
	
	pUserApi->ShowWindow(hWnd,SW_SHOWNORMAL);
	pUserApi->UpdateWindow(hWnd);
	//进入消息循环
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
	if((long)pExeWindowsInf[0].Id)		//0的id = 1 的话 认证成功
	{
		pText0 = (char*)GetRunAddress("欢迎登录");
		pText1 = (char*)GetRunAddress("登陆");
		
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