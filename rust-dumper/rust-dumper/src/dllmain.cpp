#include "core/core.hpp"

#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <cstring>

#pragma comment( lib, "shell32.lib" )

static HMODULE g_self_handle = nullptr;

static BOOL WINAPI console_ctrl( DWORD ctrl )
{
	if ( ctrl == CTRL_CLOSE_EVENT || ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT )
	{
		FreeConsole( );
		return TRUE;
	}
	return FALSE;
}

static DWORD WINAPI thread_main( LPVOID )
{
	AllocConsole( );
	SetConsoleTitleA( "rust-dumper" );
	SetConsoleCtrlHandler( console_ctrl, TRUE );
	SetConsoleOutputCP( CP_UTF8 );

	FILE* dummy = nullptr;
	freopen_s( &dummy, "CONOUT$", "w", stdout );
	freopen_s( &dummy, "CONOUT$", "w", stderr );
	std::setvbuf( stdout, nullptr, _IONBF, 0 );

	char out_dir[ MAX_PATH ]{ };
	if ( FAILED( SHGetFolderPathA( nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, out_dir ) ) )
	{
		if ( !GetEnvironmentVariableA( "TEMP", out_dir, MAX_PATH ) )
			std::strcpy( out_dir, "C:\\temp" );
	}

	char output_path[ MAX_PATH ]{ };
	std::snprintf( output_path, MAX_PATH, "%s\\rust-dumper_output.h", out_dir );

	std::printf( "[rust-dumper] starting (output: %s)\n", output_path );

	c_core core;
	if ( !core.run( output_path, true ) )
		std::printf( "[rust-dumper] run failed\n" );
	else
		std::printf( "[rust-dumper] done output written\n" );

	std::printf( "[rust-dumper] dump finished. you may close this console.\n" );
	std::fflush( stdout );

	return 0;
}

BOOL APIENTRY DllMain( HMODULE module, DWORD reason, LPVOID )
{
	if ( reason == DLL_PROCESS_ATTACH )
	{
		g_self_handle = module;
		DisableThreadLibraryCalls( module );
		CreateThread( nullptr, 0, thread_main, nullptr, 0, nullptr );
	}
	return TRUE;
}
