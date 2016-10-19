# runwithdll
windows create process with a dll load first time


sample 

```c

#include <windows.h>
#include <wchar.h>
#include <stdlib.h>


LONG RunWithDllW(__in WCHAR* pszApplication , __in_opt WCHAR* pszCommandline , __in WCHAR* pszTargetDll);


int __cdecl wmain(int nArgc, WCHAR** ppArgv)
{
	LONG nRet = -1;

	WCHAR*	pszCommandline = NULL;
	WCHAR*	pszLeftCommandline = NULL;
	ULONG	nCommandlineLen = 0;
	ULONG	nDataLen = 0;
	int		nIndex = 0;

	do 
	{
		if ( nArgc < 3 )
		{
			wprintf( L"Run Process With Dll via LdrHook \n\n");

			wprintf( L"Usage:\n");
			wprintf( L"RunWithDll.exe {Application} {TargetDll}  [Commandline]\n" );

			wprintf( L"\n");

			wprintf( L"Sample:\n");
			wprintf( L"RunWithDll.exe c:\\windows\\notepad.exe d:\\hook.dll\n" );
			wprintf( L"RunWithDll.exe c:\\windows\\notepad.exe d:\\hook.dll c:\\windows\\win.ini \n" );
			break;
		}
		
		if ( nArgc > 3 )
		{
			for ( nIndex = 3; nIndex < nArgc; nIndex++  )
			{
				nCommandlineLen += (ULONG)wcslen(  ppArgv[nIndex] ) + 3;
			}

			nCommandlineLen += 1;

			pszLeftCommandline = (WCHAR*)malloc( nCommandlineLen * sizeof(WCHAR) );
			if ( NULL == pszLeftCommandline )
			{
				break;
			}
			RtlZeroMemory( pszLeftCommandline , nCommandlineLen * sizeof(WCHAR) );

			for ( nIndex = 3; nIndex < nArgc; nIndex++  )
			{
				if ( L'"' !=  ppArgv[nIndex][0] )
				{
					wcsncpy( pszLeftCommandline + nDataLen , L"\""  , 1 );
					nDataLen += 1;
				}
				
				wcsncpy( pszLeftCommandline + nDataLen , ppArgv[nIndex]  , wcslen( ppArgv[nIndex] ) );
				nDataLen += wcslen( ppArgv[nIndex] );
				
				if ( L'"' !=  ppArgv[nIndex][0] )
				{
					wcsncpy( pszLeftCommandline + nDataLen , L"\""  , 1 );
					nDataLen += 1;
				}
			}

			pszCommandline = pszLeftCommandline;
		}
		
		RunWithDllW( ppArgv[1] ,  pszCommandline , ppArgv[2]	);
		
	} while (FALSE);

	if ( NULL != pszLeftCommandline )
	{
		free( pszLeftCommandline );
		pszLeftCommandline = NULL;
	}

	return 0;
}


```