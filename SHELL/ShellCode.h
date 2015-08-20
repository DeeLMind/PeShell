#pragma once

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<winioctl.h>


#include "StaticDataDef.h"
#include "ShellCodeStruct.h"
#include "ShellCodeFuncDef.h"



/***********************************************************/
extern SHELLCODEINF		ShellDataInf;
extern KERNEL32_API		KerApi;
extern USER32_API       UserApi;
extern SHELLWINDOWSINF  ExeWindowsInf[];