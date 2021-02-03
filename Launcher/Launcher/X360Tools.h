#pragma once
#ifndef X360TOOLS_H
#define X360TOOLS_H
 
#include <xtl.h>
#include <ppcintrinsics.h>
 
#ifdef __cplusplus
extern "C"
{
#endif
    DWORD    __stdcall    ExCreateThread(
        PHANDLE                    pHandle, 
        DWORD                    dwStackSize, 
        LPDWORD                    lpThreadId, 
        VOID*                    apiThreadStartup , 
        LPTHREAD_START_ROUTINE    lpStartAddress, 
        LPVOID                    lpParameter, 
        DWORD                    dwCreationFlagsMod
        );
 
    VOID    __cdecl        XapiThreadStartup(
        VOID    (__cdecl *StartRoutine)(VOID *), 
        VOID    *StartContext
        );
 
    UINT32    __stdcall    XexGetModuleHandle(
        char*    module, 
        PVOID    hand
        );
 
    UINT32    __stdcall    XexGetProcedureAddress(
        UINT32    hand,
        UINT32, 
        PVOID
        );
 
    DWORD                MmIsAddressValid(PVOID addr);
 
#ifdef __cplusplus
}
#endif
 
UINT32    ResolveFunct(char* modname, UINT32 ord);
DWORD    GetPressedButtons();
 
#endif