#pragma  once
#include "UpShellClass.h"
#include "stdio.h"

void main(int argc , char* argv[])
{
//  YLs�ӿǹ���
	UpShell up1;
	up1.LoadFile("C:\\Users\\Administrator\\Desktop\\PEview - ����.exe");
	up1.LoadShell("C:\\Users\\Administrator\\Desktop\\MyShell.exe");
	up1.StartUpShell();
	

}