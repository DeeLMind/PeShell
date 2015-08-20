
#include "SHELLCODE.h"

#define EXE_PE_FILE_TYPE 'EXE'
#define DLL_PE_FILE_TYPE 'DLL'
#define SYS_PE_FILE_TYPE 'SYS'
#define EXE_SHELL_TAG L"EXE_001"
#define DLL_SHELL_TAG L"DLL_002"
#define SYS_SHELL_TAG L"SYS_003"



//定义函数指针

typedef PVOID (__stdcall * PT_GetProcAddress)(PIMAGE_DOS_HEADER,char*);

typedef PIMAGE_DOS_HEADER (_stdcall* PTLoadLibraryA)(char*);

//char ExeGetModuleHandleA[]="GetModuleHandleA";//kernel32.dll
typedef PIMAGE_DOS_HEADER (_stdcall*PTGetModuleHandleA)(char*);

//char ExeExitProcess[]="ExitProcess";//kernel32.dll
typedef void (_stdcall*PTExitProcess)(unsigned int);


//char ExeRegisterClassExA[]="RegisterClassExA";//user32.dll
typedef WORD (_stdcall*PTRegisterClassExA)(WNDCLASSEXA*);

//char ExeCreateWindowExA[]="CreateWindowExA";//user32.dll
typedef HWND (_stdcall*PTCreateWindowExA)(DWORD,char*,char*,DWORD,int,int,int,int
	,HWND,HMENU,HINSTANCE,void*);

//char ExeShowWindow[]="ShowWindow";//user32.dll
typedef int (_stdcall*PTShowWindow)(HWND,int);

//char ExeUpdateWindow[]="UpdateWindow";//user32.dll
typedef int (_stdcall*PTUpdateWindow)(HWND);

//char ExeGetMessageA[]="GetMessageA";//user32.dll
typedef int (_stdcall*PTGetMessageA)(LPMSG,HWND,UINT,UINT);

//char ExeTranslateAccelerator[]="TranslateAccelerator";//user32.dll
typedef int (_stdcall*PTTranslateAccelerator)(HWND,HACCEL,LPMSG);

//char ExeTranslateMessage[]="TranslateMessage";//user32.dll
typedef int (_stdcall*PTTranslateMessage)(LPMSG);

//char ExeDispatchMessageA[]="DispatchMessageA";//user32.dll
typedef long (_stdcall*PTDispatchMessageA)(LPMSG);

//char ExeGetDlgItemTextA[]="GetDlgItemTextA";//user32.dll
typedef UINT (_stdcall*PTGetDlgItemTextA)(HWND,int,LPSTR,int);

//char ExeDefWindowProcA[]="DefWindowProcA";//user32.dll
typedef LRESULT (_stdcall*PTDefWindowProcA)(HWND,UINT,WPARAM,LPARAM);

//
typedef VOID (_stdcall*PTPostQuitMessage)(int);

//
typedef BOOL (_stdcall*PTDestroyWindow)(HWND);

//
typedef int (__stdcall*PTMessageBoxA)(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption
	,UINT uType);
