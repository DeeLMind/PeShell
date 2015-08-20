#pragma  once
#include "UpShellClass.h"
#include "stdio.h"

void main(int argc , char* argv[])
{
//  YLs加壳工具
	UpShell up1;
	up1.LoadFile("C:\\Users\\Administrator\\Desktop\\PEview - 副本.exe");
	up1.LoadShell("C:\\Users\\Administrator\\Desktop\\MyShell.exe");
	up1.StartUpShell();
	

}