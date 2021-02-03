#include "stdafx.h"

DWORD (*launchStartSysModule)(char*);
void (*RunApp)();
 
DWORD WINAPI main(void) 
{ 	
	OutputDebugStringA("Launcher for \"The Saboteur\" by Warranty Voider started\n");
    RunApp = (void (*)())(ResolveFunct("Patcher.xex", 2)); 
    if (!RunApp) 
	{
        launchStartSysModule = (DWORD (__cdecl *)(char*))(ResolveFunct("launch.xex", 2)); 
        if (!launchStartSysModule) 
		{
			OutputDebugStringA("Cant resolve function address\n");
            return 1;
        } 
        DWORD ret = launchStartSysModule("GAME:\\Patcher.xex"); 	
        if (!ret) 
		{			
            RunApp = (void (*)())(ResolveFunct("Patcher.xex", 2)); 
            if (!RunApp) 
			{				
				OutputDebugStringA("Cant resolve Patcher address\n");
                return 1;
			}
        }
        else 
		{
			char test[100];
			itoa(ret, test, 16);
			OutputDebugStringA("Failed to load Patcher.xex, Error ");
			OutputDebugStringA(test);
			OutputDebugStringA("\n");
            return 1;
		}
    }    
    RunApp(); 
    XLaunchNewImage("GAME:\\default.xex", 0);
    return 0;
}