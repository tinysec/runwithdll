// windows create process with dll loaded at first time.
// by TinySec( root@tinysec.net )
// you can free use this code , but if you had modify , send a copy to to my email please.



#include <windows.h>
#include <stdlib.h>


//////////////////////////////////////////////////////////////////////////
ULONG_PTR _RunWithDll_ALIGN_DOWN_BY( ULONG_PTR nLength , ULONG_PTR nAlign )
{
	return nLength & ~(nAlign - 1);
}

ULONG_PTR _RunWithDll_ALIGN_UP_BY( ULONG_PTR nLength , ULONG_PTR nAlign )
{
	return _RunWithDll_ALIGN_DOWN_BY( ((ULONG_PTR)(nLength) + nAlign - 1), nAlign );
}

LONG _RunWithDll_GetTargetArchitecture(__in HANDLE hTargetProcess ,  __out WORD* pwArchitecture)
{
	typedef BOOL (WINAPI *LPFN_IsWow64Process)( __in HANDLE hProcess, __out PBOOL Wow64Process);
	typedef VOID (WINAPI *LPFN_GetNativeSystemInfo)( __out LPSYSTEM_INFO lpSystemInfo );

	LONG		FinalStatus = -1;
	SYSTEM_INFO		stSysInfo = {0};
	HMODULE			hKernel32 = NULL;

	LPFN_IsWow64Process			fnIsWow64Process = NULL;
	LPFN_GetNativeSystemInfo	fnGetNativeSystemInfo = NULL;
	BOOL						bFlag = FALSE;
	BOOL						bWow64 = FALSE;

	WORD						wProcessorArchitecture = 0;


	
	do 
	{
		if (NULL == pwArchitecture)
		{
			break;
		}

		hKernel32 = GetModuleHandleA("kernel32.dll");
		if (NULL == hKernel32)
		{
			break;
		}

		fnIsWow64Process = (LPFN_IsWow64Process)GetProcAddress(hKernel32, "IsWow64Process");
		if (NULL == fnIsWow64Process)
		{
			break;
		}

		fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(hKernel32, "GetNativeSystemInfo");
		if (NULL == fnGetNativeSystemInfo)
		{
			break;
		}

		fnGetNativeSystemInfo(&stSysInfo);

		if (PROCESSOR_ARCHITECTURE_AMD64 == stSysInfo.wProcessorArchitecture)
		{
			bFlag = fnIsWow64Process(hTargetProcess , &bWow64);
			
			if (bWow64)
			{
				wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
			}
			else
			{
				wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
			}

		

			FinalStatus = 0;
		}
		else if (PROCESSOR_ARCHITECTURE_INTEL ==  stSysInfo.wProcessorArchitecture)
		{
			wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;

			FinalStatus = 0;
		}
		else
		{
			FinalStatus = -2;
		}

	} while (FALSE);

	if (NULL != pwArchitecture)
	{
		*pwArchitecture = wProcessorArchitecture;
	}

	return FinalStatus;
}


LONG _RunWithDll_RemoteGetNtdllImageBase(__in HANDLE hTargetProcess , __in BOOL bTarget64,  __out void** ppTargetNtdllImageBase)
{
	LONG		FinalStatus = -1;
	ULONG_PTR	ulRet = 0;
	BOOL		bFlag = FALSE;
	
	void*		RemoteAddress = NULL;
	ULONG64		ulValue = 0;
	ULONG_PTR	ulBytesRead = 0;

	IMAGE_NT_HEADERS32*			pNtHeader32 = NULL;
	IMAGE_EXPORT_DIRECTORY*		pExportDir = NULL;

	ULONG						FindAddress = 0;

	MEMORY_BASIC_INFORMATION	stMemBasicInfo = {0};
	ULONG						ulRegionSize = 0;

	char* pszDllName = NULL;


	do 
	{
		if ( NULL == ppTargetNtdllImageBase)
		{
			break;
		}

#ifdef _WIN64
		if (bTarget64)
		{	
			*ppTargetNtdllImageBase = GetModuleHandleA("ntdll.dll");
			FinalStatus = 0;
			break;
		}
#else
		if (!bTarget64)
		{
			*ppTargetNtdllImageBase = GetModuleHandleA("ntdll.dll");
			FinalStatus = 0;
			break;
		}
		else
		{
			FinalStatus = 0xC00000BBL;
			break;
		}
#endif //_WIN64
				
		// need search , bTarget64 must false

		pszDllName = (CHAR*)malloc( MAX_PATH );
		if (NULL == pszDllName)
		{
			break;
		}
		RtlZeroMemory(pszDllName, MAX_PATH);
		
		pNtHeader32 = (IMAGE_NT_HEADERS32*)malloc( sizeof(IMAGE_NT_HEADERS32) );
		if (NULL == pNtHeader32)
		{
			break;
		}
		RtlZeroMemory(pNtHeader32, sizeof(IMAGE_NT_HEADERS32));

		pExportDir = (IMAGE_EXPORT_DIRECTORY*)malloc( sizeof(IMAGE_EXPORT_DIRECTORY));
		if (NULL == pExportDir)
		{
			break;
		}
		RtlZeroMemory(pExportDir , sizeof(IMAGE_EXPORT_DIRECTORY));

		for (FindAddress = 0x10000; FindAddress < 0x7FFF0000; FindAddress += ulRegionSize)
		{
			RtlZeroMemory(&stMemBasicInfo, sizeof(stMemBasicInfo));

			ulRet = VirtualQueryEx(
				hTargetProcess,
				(void*)FindAddress,
				&stMemBasicInfo,
				sizeof(stMemBasicInfo)
			);

			if (0 == ulRet)
			{
				ulRegionSize = 0x10000;
				continue;
			}

			if ( ( MEM_COMMIT != (stMemBasicInfo.State & MEM_COMMIT) ) || (PAGE_NOACCESS == stMemBasicInfo.Protect) )
			{
				ulRegionSize = (ULONG)_RunWithDll_ALIGN_UP_BY(stMemBasicInfo.RegionSize , 0x10000);
				continue;
			}


			//IMAGE_DOS_SIGNATURE
			ulValue = 0;

			bFlag = ReadProcessMemory(hTargetProcess,
				(void*)FindAddress,
				&ulValue,
				sizeof(WORD),
				&ulBytesRead
			);
			if (!bFlag)
			{
				ulRegionSize = 0x10000;
				continue;
			}

			if (IMAGE_DOS_SIGNATURE != (WORD)ulValue )
			{
				ulRegionSize = 0x10000;
				continue;
			}
			
			// e_flnew
			ulValue = 0;

			bFlag = ReadProcessMemory(hTargetProcess,
				(void*)( FindAddress + FIELD_OFFSET(IMAGE_DOS_HEADER,e_lfanew) ),
				&ulValue,
				sizeof(ULONG),
				&ulBytesRead
			);
			if (!bFlag)
			{
				ulRegionSize = 0x10000;
				continue;
			}
			
			RtlZeroMemory(pNtHeader32, sizeof(IMAGE_NT_HEADERS32));

			bFlag = ReadProcessMemory(hTargetProcess,
				(void*)( FindAddress + (USHORT)ulValue ),
				pNtHeader32,
				sizeof(IMAGE_NT_HEADERS32),
				&ulBytesRead
			);
			if (!bFlag)
			{
				ulRegionSize = 0x10000;
				continue;
			}

			if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
			{
				ulRegionSize = 0x10000;
				continue;
			}
		
			ulRegionSize = (ULONG)_RunWithDll_ALIGN_UP_BY( pNtHeader32->OptionalHeader.SizeOfImage , 0x10000);

			if ( IMAGE_FILE_DLL != (IMAGE_FILE_DLL & pNtHeader32->FileHeader.Characteristics) )
			{
				continue;
			}

			if ( (0 == pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) \
				|| (0 == pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			)
			{
				continue;
			}

			RtlZeroMemory(pExportDir , sizeof(IMAGE_EXPORT_DIRECTORY) );

			RemoteAddress = (void*)( FindAddress + pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

			bFlag = ReadProcessMemory(hTargetProcess,
				RemoteAddress,
				pExportDir,
				sizeof(IMAGE_EXPORT_DIRECTORY),
				&ulBytesRead
			);
			if (!bFlag)
			{
				continue;
			}

			if ( 0 == pExportDir->Name)
			{
				continue;
			}

			RtlZeroMemory(pszDllName, MAX_PATH);
	
			bFlag = ReadProcessMemory(hTargetProcess,
				(void*)(FindAddress + pExportDir->Name),
				pszDllName,
				MAX_PATH,
				&ulBytesRead
			);
			if (!bFlag)
			{
				continue;
			}

			if ( 0 == _stricmp(pszDllName,"ntdll.dll") )
			{
				*ppTargetNtdllImageBase = (void*)FindAddress;
				FinalStatus = 0;
				break;
			}
		}

	} while (FALSE);

	if (NULL != pNtHeader32)
	{
		free(pNtHeader32);	
		pNtHeader32 = NULL;
	}
	
	if ( NULL != pExportDir)
	{
		free(pExportDir);
		pExportDir = NULL;
	}

	if ( NULL != pszDllName)
	{
		free(pszDllName);
		pszDllName = NULL;
	}

	return FinalStatus;
}

LONG _RunWithDll_RemoteGetProcAddress(__in HANDLE hTargetProcess , __in BOOL bTarget64 , __in void* ModuleImageBase , __in char* pszRoutineName , __out void** ppRoutineAddress)
{	
	LONG	FinalStatus = -1;
	BOOL		bFlag = FALSE;
	

	ULONG64		ulValue = 0;
	ULONG_PTR	ulBytesRead = 0;

	void*		RemoteAddress = NULL;
	
	IMAGE_NT_HEADERS64*		pNtHeader64 = NULL;
	IMAGE_NT_HEADERS32*		pNtHeader32 = NULL;
	IMAGE_EXPORT_DIRECTORY*	pExportDir = NULL; 
	ULONG					i = 0;

	char*	pszFindName = NULL;

	do 
	{
		if ( (0 == ModuleImageBase) || (NULL == pszRoutineName) || (NULL == ppRoutineAddress) )
		{
			break;
		}

		ulValue = 0;
		bFlag = ReadProcessMemory(hTargetProcess,
			(UCHAR*)ModuleImageBase + FIELD_OFFSET(IMAGE_DOS_HEADER ,e_lfanew),
			&ulValue,
			sizeof(WORD),
			&ulBytesRead
		);
		if (!bFlag)
		{
			break;
		}

		pszFindName = (CHAR*)malloc( MAX_PATH);
		if (NULL == pszFindName)
		{
			break;
		}
		RtlZeroMemory(pszFindName, MAX_PATH);

		if (bTarget64)
		{
			pNtHeader64 = (IMAGE_NT_HEADERS64*)malloc( sizeof(IMAGE_NT_HEADERS64) );
			if (NULL == pNtHeader64)
			{
				break;
			}
			RtlZeroMemory(pNtHeader64, sizeof(IMAGE_NT_HEADERS64));
			
			bFlag = ReadProcessMemory(hTargetProcess,
				(UCHAR*)ModuleImageBase + (USHORT)ulValue,
				pNtHeader64,
				sizeof(IMAGE_NT_HEADERS64),
				&ulBytesRead
			);
			if (!bFlag)
			{
				break;
			}
			
			if ( (0 == pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) \
				|| (0 == pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			)
			{
				break;
			}

			RemoteAddress = (UCHAR*)ModuleImageBase + pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else
		{
			pNtHeader32 = (IMAGE_NT_HEADERS32*)malloc( sizeof(IMAGE_NT_HEADERS32));
			if (NULL == pNtHeader32)
			{
				break;
			}
			RtlZeroMemory(pNtHeader32, sizeof(IMAGE_NT_HEADERS32));
			
			bFlag = ReadProcessMemory(hTargetProcess,
				(UCHAR*)ModuleImageBase + (USHORT)ulValue,
				pNtHeader32,
				sizeof(IMAGE_NT_HEADERS32),
				&ulBytesRead
			);
			if (!bFlag)
			{
				break;
			}
			
			if ( (0 == pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) \
				|| (0 == pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			)
			{
				break;
			}

			RemoteAddress = (UCHAR*)ModuleImageBase + pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		

		pExportDir = (IMAGE_EXPORT_DIRECTORY*)malloc( sizeof(IMAGE_EXPORT_DIRECTORY));
		if (NULL == pExportDir)
		{
			break;
		}
		RtlZeroMemory(pExportDir , sizeof(IMAGE_EXPORT_DIRECTORY) );
		
		bFlag = ReadProcessMemory(hTargetProcess,
			RemoteAddress,
			pExportDir,
			sizeof(IMAGE_EXPORT_DIRECTORY),
			&ulBytesRead
		);
		if (!bFlag)
		{
			break;
		}

		FinalStatus = 0xC0000225L;
		for (i = 0; i < pExportDir->NumberOfNames; i++)
		{
			RemoteAddress = (UCHAR*)ModuleImageBase + pExportDir->AddressOfNames + i * sizeof(ULONG);

			RtlZeroMemory(pszFindName, MAX_PATH);

			//Read Name RVA
			ulValue = 0;
			bFlag = ReadProcessMemory(hTargetProcess,
				RemoteAddress,
				&ulValue,
				sizeof(ULONG),
				&ulBytesRead
			);
			if (!bFlag)
			{
				continue;
			}
			
			bFlag = ReadProcessMemory(hTargetProcess,
				(UCHAR*)ModuleImageBase + (ULONG)ulValue,
				pszFindName,
				MAX_PATH,
				&ulBytesRead	
			);
			if (!bFlag)
			{
				continue;
			}


			if ( 0 == _stricmp(pszFindName , pszRoutineName) )
			{
				//Read wNameOrdinal
				RemoteAddress = (USHORT*)( (UCHAR*)ModuleImageBase + pExportDir->AddressOfNameOrdinals ) + i;

				ulValue = 0;
				bFlag = ReadProcessMemory(hTargetProcess,
					RemoteAddress,
					&ulValue,
					sizeof(USHORT),
					&ulBytesRead
				);
				if (bFlag)
				{
					if ( (USHORT)ulValue < pExportDir->NumberOfFunctions)
					{
						//Read Address RVA
						
						RemoteAddress = (ULONG*)( (UCHAR*)ModuleImageBase + pExportDir->AddressOfFunctions) + (USHORT)ulValue;

						ulValue = 0;
						bFlag = ReadProcessMemory(hTargetProcess,
							RemoteAddress,
							&ulValue,
							sizeof(ULONG),
							&ulBytesRead
						);
						if (bFlag)
						{
							*ppRoutineAddress = (void*)( (UCHAR*)ModuleImageBase + (ULONG)ulValue);
							FinalStatus = 0;
							break;
						}
					}
				}
			}
		}
	
	} while (FALSE);

	if ( NULL != pszFindName)
	{
		free(pszFindName);
		pszFindName = NULL;
	}

	if ( NULL != pExportDir )
	{
		free(pExportDir);
		pExportDir = NULL;
	}

	if ( NULL != pNtHeader32 )
	{
		free(pNtHeader32);
		pNtHeader32 = NULL;
	}

	if ( NULL != pNtHeader64 )
	{
		free( pNtHeader64 );
		pNtHeader64 = NULL;
	}

	return FinalStatus;
}


LONG _RunWithDll_RemoteWriteString(__in HANDLE hProcess , __in BOOL bTarget64,  __in WCHAR* pszString , __out void** ppRemoteUnicodeString)
{
	#pragma pack(push,1)

	// 0x08
	typedef struct _UNICODE_STRING32
	{
		USHORT	Length;				//0x00
		USHORT	MaximumLength;		//0x00
		ULONG   Buffer;				//0x04
	} UNICODE_STRING32;		

	#pragma pack(pop)

	// 0x10 
	typedef struct _UNICODE_STRING64
	{
		USHORT	Length;				//0x00
		USHORT	MaximumLength;		//0x02
		ULONG64 Buffer;				//0x08
	} UNICODE_STRING64;

	

	LONG		FinalStatus = -1;
	
	int				nSize = 0;

	int				nWideSize = 0;

	UNICODE_STRING32	usHelp32 = {0};
	UNICODE_STRING64	usHelp64 = {0};

	void*			pRemoteBuffer = NULL;
	void*			pRemoteStr = NULL;
	ULONG_PTR		BytesWritten = 0;

	int				nRet = -1;
	BOOL			bFlag = FALSE;


	do 
	{
		if ( (NULL == pszString) || (NULL == ppRemoteUnicodeString) )
		{
			break;
		}
		

		nWideSize = (int)( (wcslen(pszString) ) * sizeof(WCHAR) );
		
		if (bTarget64)
		{
			nSize = nWideSize  + sizeof(WCHAR) + 0x10;
		}
		else
		{
			nSize = nWideSize + sizeof(WCHAR) + 0x08;
		}

		pRemoteBuffer = VirtualAllocEx(
			hProcess ,
			NULL, 
			nSize,
			MEM_COMMIT |MEM_RESERVE ,
			PAGE_READWRITE
		);
		if (NULL == pRemoteBuffer)
		{
			break;
		}
		
		// write Struct
		if (bTarget64)
		{
			usHelp64.Length			= (USHORT) nWideSize;
			usHelp64.MaximumLength	= usHelp64.Length + sizeof(WCHAR);
			usHelp64.Buffer			= (ULONG64)( (UCHAR*)pRemoteBuffer + 0x10 );

			pRemoteStr = (void*)usHelp64.Buffer;
		}
		else
		{
			usHelp32.Length			= (USHORT) nWideSize;
			usHelp32.MaximumLength	= usHelp32.Length + sizeof(WCHAR);
			usHelp32.Buffer			= (ULONG)( (UCHAR*)pRemoteBuffer + 0x08 );

			pRemoteStr = (void*)usHelp32.Buffer;
		}

		
		if (bTarget64)
		{
			bFlag = WriteProcessMemory(hProcess,
				pRemoteBuffer,
				&usHelp64,
				sizeof(usHelp64),
				&BytesWritten
			);
		}
		else
		{
			bFlag = WriteProcessMemory(hProcess,
				pRemoteBuffer,
				&usHelp32,
				sizeof(usHelp32),
				&BytesWritten
			);
		}

		if (!bFlag)
		{
			break;
		}
		
		// write buffer
		bFlag = WriteProcessMemory(hProcess,
			pRemoteStr,
			pszString,
			nWideSize + sizeof(WCHAR),
			&BytesWritten
		);
		if (!bFlag)
		{
			break;
		}
		
		*ppRemoteUnicodeString = pRemoteBuffer;
		
		FinalStatus = 0;
	} while (FALSE);
	
	return FinalStatus;
}


PVOID _RunWithDll_FindULONG32(__in PVOID pBase , __in ULONG nRange , __in ULONG nMagic )
{
	ULONG	ulIndex=0;
	PVOID	pFind=NULL;
	DWORD*	pdwTemp=NULL;
	
	do 
	{
		if ( (NULL == pBase)  )
		{
			break;
		}
		
		if ( nRange < sizeof(ULONG) )
		{
			break;
		}
		
		for (ulIndex=0; ulIndex < (nRange - sizeof(ULONG)) ; ulIndex++)
		{
			pdwTemp = (ULONG*)((UCHAR*)pBase + ulIndex);
			if ( nMagic == (*pdwTemp) )
			{
				pFind = (PVOID)pdwTemp;
				break;
			}
		}
		
	} while (FALSE);
	
	return pFind;
}

PVOID _RunWithDll_ReplaceULONG32(__in PVOID pAddr , __in ULONG nRange , __in ULONG nMagic , __in ULONG nValue , __in BOOLEAN bReplaceAll )
{
	UCHAR* pPos = NULL;
	UCHAR* pReturn = NULL;
	
	do 
	{
		if ( (NULL == pAddr) || (0 == nRange) )
		{
			break;
		}
		
		if (nRange < sizeof(ULONG))
		{
			break;
		}
		
		
		for (pPos = (UCHAR*)pAddr; pPos <= (UCHAR*)pAddr + nRange - sizeof(ULONG); )
		{
			
			if ( *(ULONG*)pPos == nMagic )
			{
				*(ULONG*)pPos = nValue;
				
				if (bReplaceAll)
				{
					pPos += sizeof(ULONG);
				}
				else
				{
					pReturn = pPos + sizeof(ULONG);
					
					break;
				}
			}
			else
			{
				pPos++;
			}
		}
		
	} while (FALSE);
	
	return pReturn;
}

PVOID _RunWithDll_ReplaceULONG64(__in PVOID pAddr , __in ULONG nRange , __in ULONG64 nMagic , __in ULONG64 nValue , __in BOOLEAN bReplaceAll)
{
	UCHAR* pPos = NULL;
	UCHAR* pReturn = NULL;

	do 
	{
		if ( (NULL == pAddr) || (0 == nRange) )
		{
			break;
		}
		
		if (nRange < sizeof(ULONG64))
		{
			break;
		}
		
		for (pPos = (UCHAR*)pAddr; pPos <= (UCHAR*)pAddr + nRange - sizeof(ULONG64) ; )
		{
			if ( *( (ULONG64*)pPos ) == nMagic)
			{
				*( (ULONG64*)pPos ) = nValue;
				
				if (bReplaceAll)
				{
					pPos += sizeof(ULONG64);
				}
				else
				{
					pReturn = pPos + sizeof(ULONG64);
					
					break;
				}
			}
			else
			{
				pPos++;
			}
		}
		
	} while (FALSE);
	
	return pReturn;
}

LONG _RunWithDll_BuildHookLdrLoadDllShellCode(__in HANDLE hTargetProcess , __in BOOL bTarget64 , __in void* pRemoteUnicodeString , __in void* pRemoteLdrLoadDll , __out void** ppCode , __out ULONG* pulCodeSize)
{	
	LONG		FinalStatus = -1;
	void*		pOriginCode = NULL;

	void*		pShellcode = NULL;
	ULONG		ulCodeSize = 0;
	ULONG_PTR	ulBytesRead = 0;
	BOOL		bFlag = FALSE;

	unsigned char amd64_template[166] = {
			0x90, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00,
			0x9C, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41,
			0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x56, 0x57, 0x51, 0x52, 0xEB, 0x68, 0x48, 0xBF, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, 0xF3, 0xA4,
			0x5A, 0x59, 0x5F, 0x5E, 0x4C, 0x8D, 0x4D, 0xE0, 0x49, 0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
			0x22, 0x22, 0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0x81, 0xEC, 0x08,
			0x01, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x81, 0xC4, 0x08, 0x01, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E,
			0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5A, 0x59,
			0x5B, 0x58, 0x9D, 0x48, 0x8B, 0xE5, 0x5D, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x48, 0x83, 0xC6, 0x07, 0xEB,
			0x8C, 0x33, 0x33, 0x33, 0x33, 0x90
	};

	unsigned char i386_template[83] = {
			0x90, 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, 0x9C, 0x60, 0x56,
			0x57, 0x51, 0xEB, 0x2F, 0xBF, 0x11, 0x11, 0x11, 0x11, 0xB9, 0x05, 0x00, 0x00, 0x00, 0xF3, 0xA4,
			0x59, 0x5F, 0x5E, 0x8D, 0x45, 0xE0, 0x50, 0x68, 0x22, 0x22, 0x22, 0x22, 0x6A, 0x00, 0xFF, 0x75,
			0x08, 0xB8, 0x11, 0x11, 0x11, 0x11, 0xFF, 0xD0, 0x61, 0x9D, 0x8B, 0xE5, 0x5D, 0x68, 0x11, 0x11,
			0x11, 0x11, 0xC3, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x83, 0xC6, 0x06, 0xEB, 0xC6, 0x33, 0x33,
			0x33, 0x33, 0x90
	};

	
	do 
	{
		if ( (0 == pRemoteUnicodeString) || (0 == pRemoteLdrLoadDll) || (NULL == ppCode) || (NULL == pulCodeSize) )
		{
			break;
		}

		if (bTarget64)
		{
			ulCodeSize = sizeof(amd64_template);
		}
		else
		{
			ulCodeSize = sizeof(i386_template);
		}
		
		pShellcode = malloc( ulCodeSize);
		if (NULL == pShellcode)
		{
			break;
		}
		RtlZeroMemory(pShellcode , ulCodeSize);

		if (bTarget64)
		{
			RtlCopyMemory(pShellcode , amd64_template , sizeof(amd64_template));
		}
		else
		{
			RtlCopyMemory(pShellcode , i386_template , sizeof(i386_template));
		}

		if (bTarget64)
		{
			_RunWithDll_ReplaceULONG64(
				pShellcode,
				ulCodeSize,
				(ULONG64)0x1111111111111111,
				(ULONG64)pRemoteLdrLoadDll,
				TRUE				
			);

			_RunWithDll_ReplaceULONG64(
				pShellcode,
				ulCodeSize,
				(ULONG64)0x2222222222222222,
				(ULONG64)pRemoteUnicodeString,
				TRUE				
			);
		}
		else
		{
			_RunWithDll_ReplaceULONG32(
				pShellcode,
				ulCodeSize,
				(ULONG64)0x11111111,
				(ULONG)((ULONG64)pRemoteLdrLoadDll),
				TRUE				
			);
			
			_RunWithDll_ReplaceULONG32(
				pShellcode,
				ulCodeSize,
				(ULONG64)0x22222222,
				(ULONG)((ULONG64)pRemoteUnicodeString),
				TRUE				
			);
		}

		pOriginCode = _RunWithDll_FindULONG32(
			pShellcode,
			ulCodeSize,
			(ULONG)0x33333333
		);
		if (NULL == pOriginCode)
		{
			break;
		}
		
		bFlag = ReadProcessMemory(hTargetProcess,
			pRemoteLdrLoadDll,
			pOriginCode,
			5,
			&ulBytesRead
		);
		if (!bFlag)
		{
			break;
		}

		*ppCode = pShellcode;
		*pulCodeSize = ulCodeSize;

		FinalStatus = 0;
	} while (FALSE);

	if (0 != FinalStatus)
	{
		if ( NULL != pShellcode)
		{
			free(pShellcode);
			pShellcode = NULL;
		}
	}

	return FinalStatus;
}

LONG _RunWithDll_RemoteAllocNearPageMemory(	__in HANDLE	hProcess , __in BOOL bTarget64, __in void* pNearBase ,  __in ULONG ulNeedSize , __in ULONG ulRangeSize , __out void** ppAllocatedMemAddress)
{
	LONG		Status = -1;	
	LONG		FinalStatus = -1;
	MEMORY_BASIC_INFORMATION stMemBasicInfo = {0};
	ULONG_PTR	QueryAddress = (ULONG_PTR)pNearBase;
	ULONG_PTR	TryAddress = 0;
	void*		MemAddress = NULL;
	void*		FinalAddress = NULL;
	ULONG		ulPageSize = 0;
	
	do 
	{
		if (bTarget64)
		{
			ulPageSize = 1024 * 8;
		}
		else
		{
			ulPageSize = 1024 * 4;
		}
		
		for ( QueryAddress = (ULONG_PTR)pNearBase ; QueryAddress < (ULONG_PTR)pNearBase + ulRangeSize ; QueryAddress = QueryAddress + stMemBasicInfo.RegionSize)
		{
			RtlZeroMemory(&stMemBasicInfo, sizeof(stMemBasicInfo));

			VirtualQueryEx(hProcess, (void*)QueryAddress, &stMemBasicInfo, sizeof(stMemBasicInfo));

			if ( MEM_FREE != stMemBasicInfo.State)
			{
				continue;
			}
			
			Status = -1;	
			for ( TryAddress = QueryAddress; TryAddress < QueryAddress +  stMemBasicInfo.RegionSize; TryAddress = TryAddress + ulPageSize)
			{
				MemAddress = VirtualAllocEx(hProcess , (void*)TryAddress, ulNeedSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (NULL != MemAddress)
				{
					Status = 0;
					break;
				}
			}
			
			if (0 == Status)
			{
				FinalAddress = MemAddress;
				FinalStatus = 0;
				break;
			}
		}
		
	} while (FALSE);
	
	if (NULL != ppAllocatedMemAddress)
	{
		*ppAllocatedMemAddress = FinalAddress;
	}
	
	return FinalStatus;
}

LONG _RunWithDll_RemoteWriteJump( __in HANDLE hTargetProcess , __in void* SourceAddress , __in void* DestAddress)
{
	LONG	FinalStatus = -1;
	
	UCHAR		JumpCode[5] = {0};
	
	ULONG64		Distance = 0;
	
	ULONG64		NextCode = 0;
	LONG		DisValue = 0;
	ULONG_PTR	BytesWritten = 0;
	BOOL		bFlag = FALSE;
	
	do 
	{
		if ( (NULL == SourceAddress) || (NULL == DestAddress) )
		{
			break;
		}
		
		if ( (ULONG64)SourceAddress > (ULONG64)DestAddress  )
		{
			Distance = (ULONG64)SourceAddress - (ULONG64)DestAddress;
		}
		else
		{
			Distance = (ULONG64)DestAddress - (ULONG64)SourceAddress;
		}
		
		if ( Distance > 0x7FFF0000)
		{
			break;
		}
		
		NextCode = (ULONG64)SourceAddress + 5;
		
		DisValue = (LONG)((LONG64)DestAddress - (LONG64)NextCode);
		
		*( (UCHAR*)JumpCode + 0x00 ) = 0xE9;

		*( (ULONG*)( (UCHAR*)JumpCode + 1 ) ) = DisValue;
		
		bFlag = WriteProcessMemory(hTargetProcess,
			SourceAddress,
			JumpCode,
			sizeof(JumpCode),
			&BytesWritten
		);
		if (!bFlag)
		{
			break;
		}
		
		FinalStatus = 0;
	} while (FALSE);
	
	return FinalStatus;
}

LONG _RunWithDll_LdrInject(__in HANDLE hTargetProcess , __in WCHAR* pszTargetDll)
{
	LONG FinalStatus = -1;
	LONG Status = 0;
	WORD	wArchitecture = 0;
	BOOL	bTarget64 = FALSE;
	BOOL	bFlag = FALSE;

	void*	TargetNtdllImageBase = NULL;
	void*	TargetLdrLoadDll = NULL;
	void*	RemoteUnicodeStringDll = NULL;

	void*	pLocalShellCode = NULL;
	ULONG	ulShellCodeSize = 0;
	void*	pRemoteShellcode = NULL;
	ULONG_PTR	ulBytesWriten = 0;
	DWORD		dwOldProtect = 0;

	do 
	{
		if (  (NULL == hTargetProcess) || (NULL == pszTargetDll) )
		{
			break;
		}

		Status = _RunWithDll_GetTargetArchitecture(hTargetProcess , &wArchitecture);
		if (0 != Status)
		{
			break;
		}

		if ( PROCESSOR_ARCHITECTURE_AMD64 == wArchitecture)
		{
			bTarget64 = TRUE;
		}
		else
		{
			bTarget64 = FALSE;
		}

		Status = _RunWithDll_RemoteWriteString(hTargetProcess, bTarget64, pszTargetDll, &RemoteUnicodeStringDll);
		if (0 != Status)
		{
			break;
		}

		Status = _RunWithDll_RemoteGetNtdllImageBase(hTargetProcess, bTarget64, &TargetNtdllImageBase);
		if (0 != Status)
		{
			break;
		}

		Status =  _RunWithDll_RemoteGetProcAddress(
			hTargetProcess, 
			bTarget64,
			TargetNtdllImageBase,
			"LdrLoadDll",
			&TargetLdrLoadDll
		);
		if (0 != Status)
		{
			break;
		}

		Status = _RunWithDll_BuildHookLdrLoadDllShellCode(
			hTargetProcess,
			bTarget64,
			RemoteUnicodeStringDll,
			TargetLdrLoadDll,
			&pLocalShellCode,
			&ulShellCodeSize
		);
		if (0 != Status)
		{
			break;
		}

		Status = _RunWithDll_RemoteAllocNearPageMemory(
			hTargetProcess,
			bTarget64,
			TargetNtdllImageBase,
			ulShellCodeSize,
			0x7FFF0000,
			&pRemoteShellcode
		);
		if (0 != Status)
		{
			break;
		}
		
		bFlag = WriteProcessMemory(
			hTargetProcess,
			pRemoteShellcode,
			pLocalShellCode,
			ulShellCodeSize,
			&ulBytesWriten
		);
		
		if (!bFlag)
		{
			break;
		}

		bFlag = VirtualProtectEx(hTargetProcess,
			(void*)TargetLdrLoadDll, 
			5 ,
			PAGE_EXECUTE_READWRITE ,
			&dwOldProtect
		);
		if (!bFlag)
		{
			break;
		}
		
		Status = _RunWithDll_RemoteWriteJump(hTargetProcess , TargetLdrLoadDll,	pRemoteShellcode);
		if (0 != Status)
		{
			break;
		}

		FinalStatus = 0;
	} while (FALSE);

	if ( NULL != pLocalShellCode)
	{
		free( pLocalShellCode );
		pLocalShellCode = NULL;
	}

	return FinalStatus;
}


LONG RunWithDllW(__in WCHAR* pszApplication , __in_opt WCHAR* pszCommandline , __in WCHAR* pszTargetDll)
{
	LONG	nFinalRet = -1;
	LONG	nRet = -1;
	
	STARTUPINFOW			stStartupInfo = {0};
	PROCESS_INFORMATION		stProcessInfo = {0};

	ULONG					nApplicationLen = 0;
	ULONG					nCommandlineLen = 0;

	ULONG					nFixedLen = 0;
	WCHAR*					pszFixedCommandLine = NULL;
	ULONG					nDataLen = 0;
	BOOL					bNeedFree = FALSE;
	
	BOOL	bFlag = FALSE;
	
	
	do 
	{
		stStartupInfo.cb = sizeof(stStartupInfo);

		if ( NULL == pszCommandline )
		{
			pszFixedCommandLine = NULL;
		}
		else
		{
			nApplicationLen = (ULONG)wcslen( pszApplication );
			nCommandlineLen = (ULONG)wcslen( pszCommandline );

			nFixedLen = nApplicationLen + 1 + nCommandlineLen + 1;

			pszFixedCommandLine = (WCHAR*)malloc( nFixedLen * sizeof(WCHAR) );
			if ( NULL == pszFixedCommandLine )
			{
				break;
			}
			RtlZeroMemory( pszFixedCommandLine , nFixedLen * sizeof(WCHAR) );

			bNeedFree = TRUE;

			nDataLen = 0;

			wcsncpy( pszFixedCommandLine + nDataLen, pszApplication , nApplicationLen );
			nDataLen += nApplicationLen;

			wcsncpy( pszFixedCommandLine + nDataLen , L" " , 1 );
			nDataLen += 1;

			wcsncpy( pszFixedCommandLine + nDataLen , pszCommandline , nCommandlineLen);
			nDataLen += nCommandlineLen;
		}
		
		bFlag = CreateProcessW(
			pszApplication,
			pszFixedCommandLine,
			NULL,
			NULL,
			TRUE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&stStartupInfo,
			&stProcessInfo
		);
		
		if ( !bFlag)
		{
			break;
		}
		
		nRet = _RunWithDll_LdrInject( stProcessInfo.hProcess , pszTargetDll );
		if ( 0 != nRet)
		{
			break;
		}
		
		ResumeThread( stProcessInfo.hThread);
		
		WaitForSingleObject( stProcessInfo.hProcess , INFINITE );
		
		nFinalRet = 0;
		
	} while (FALSE);
	
	if ( 0 != nFinalRet)
	{
		if (NULL != stProcessInfo.hProcess)
		{
			TerminateProcess( stProcessInfo.hProcess , 0 );
		}
		
		if (NULL != stProcessInfo.hThread)
		{
			TerminateThread( stProcessInfo.hThread , 0 );
		}
	}
	
	if (NULL != stProcessInfo.hProcess)
	{
		CloseHandle(stProcessInfo.hProcess);
		stProcessInfo.hProcess = NULL;
	}
	
	if (NULL != stProcessInfo.hThread)
	{
		CloseHandle(stProcessInfo.hThread);
		stProcessInfo.hThread = NULL;
	}

	if ( bNeedFree )
	{
		if ( NULL != pszFixedCommandLine )
		{
			free( pszFixedCommandLine );
			pszFixedCommandLine = NULL;
		}
	}
	
	return nFinalRet;
}