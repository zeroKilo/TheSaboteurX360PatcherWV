#include <xtl.h>
#include "kernel.h"

static void MainThread()
{
	OutputDebugStringA("Patcher main thread started\n");
	while(true)
	{
		Sleep(10);
		if(XamGetCurrentTitleId() == 0x4541088F)
		{
			OutputDebugStringA("Detected 'The Saboteur' is running now\n");
			char buff[100];
			DWORD* nopPtr = (DWORD*)0x823e5e18;
			sprintf(buff, "Reading from 0x823e5e18 = 0x%x\n", *nopPtr);
			OutputDebugStringA(buff);
			*nopPtr = 0x60000000;
			OutputDebugStringA("Patched Position 1\n");
			nopPtr = (DWORD*)0x823e5eb4;
			sprintf(buff, "Reading from 0x823e5eb4 = 0x%x\n", *nopPtr);
			OutputDebugStringA(buff);
			*nopPtr = 0x60000000;
			OutputDebugStringA("Patched Position 2\n");
			while(XamGetCurrentTitleId() == 0x4541088F)
			{
				Sleep(100);
			}
			OutputDebugStringA("Detected 'The Saboteur' has stopped\n");
		}
	}
}

extern "C" const TCHAR szModuleName[] = TEXT("Patcher.dll");

extern "C" void Initialize( void )
{
	return;
}

BOOL APIENTRY DllMain(HANDLE hInstDLL, DWORD reason, LPVOID lpReserved)
{
	switch( reason )
	{
		case DLL_PROCESS_ATTACH:
			OutputDebugStringA("Patcher loaded\n");
			OutputDebugStringA("Resolving XamGetCurrentTitleId\n");	
			XamGetCurrentTitleId = (UINT32 (*)(void))(ResolveFunct("xam.xex", 0x1CF));	
			if(!XamGetCurrentTitleId)
			{
				OutputDebugStringA("XamGetCurrentTitleId not found\n");
				return FALSE;	
			}
			HANDLE hThread;
			DWORD hThreadId;
			ExCreateThread(&hThread, 0, &hThreadId, (VOID*)XapiThreadStartup , (LPTHREAD_START_ROUTINE)MainThread, NULL, 0x2);
			XSetThreadProcessor(hThread, 3);
			ResumeThread(hThread);
			CloseHandle(hThread);
		break;
	}
	return TRUE;
}