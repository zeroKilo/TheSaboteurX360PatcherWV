#include "stdafx.h"
 
UINT32 ResolveFunct(char* modname, UINT32 ord) {
    UINT32 ptr32 = 0, ret = 0, ptr2 = 0;
    ret = XexGetModuleHandle(modname, &ptr32);
    if(ret == 0) {
        ret = XexGetProcedureAddress(ptr32, ord, &ptr2);
        if(ptr2 != 0)
            return(ptr2);
    }
    return(0);
}
 
DWORD GetPressedButtons() {
    XINPUT_STATE xstate;
 
    if (XInputGetState(0, &xstate) == ERROR_SUCCESS)
        return xstate.Gamepad.wButtons;
    else
        return (DWORD)-1;
}