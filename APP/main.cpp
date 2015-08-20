#pragma  once
#include "UpShellClass.h"
#include "stdio.h"

void main(int argc , char* argv[])
{

	UpShell up1;
	up1.LoadFile("C:\\xxx");		// file path 
	up1.LoadShell("C:\\aaa");		// shell path
	up1.StartUpShell();
	

}
