// PESHELL.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "ShellCode.h"
#pragma comment(linker, "/merge:Mydata=Mycode")
//���ð�ExeShell�ڱ������ӳɣ��ɶ�����д����ִ�н�
#pragma comment(linker,"/SECTION:Mycode,ERW")

void main()
{
//	InlineShell1();		//����
	ExeShellCodeMain(0,0,0,0);
	

}

