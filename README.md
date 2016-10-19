# runwithdll
windows create process with a dll load first time


sample 

```c
#include <windows.h>
#include <wchar.h>

// declare
LONG RunWithDllW(__in WCHAR* pszApplication , __in_opt WCHAR* pszCommandline , __in WCHAR* pszTargetDll);


int __cdecl wmain(int nArgc, WCHAR** ppArgv)
{

#ifdef _WIN64
	RunWithDllW(L"D:\\test64.exe" , NULL ,	L"d:\\root\\test64.dll"	);
#else
	RunWithDllW(L"D:\\test32.exe" , NULL ,	L"d:\\root\\test32.dll"	);
#endif
		
	return 0;
}


```