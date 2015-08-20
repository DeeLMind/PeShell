// PESHELL.cpp : 定义控制台应用程序的入口点。
//

#include "ShellCode.h"
#pragma comment(linker, "/merge:Mydata=Mycode")
//设置把ExeShell节编译链接成：可读、可写、可执行节
#pragma comment(linker,"/SECTION:Mycode,ERW")

void main()
{
//	InlineShell1();		//加密
	ExeShellCodeMain(0,0,0,0);
	

}

