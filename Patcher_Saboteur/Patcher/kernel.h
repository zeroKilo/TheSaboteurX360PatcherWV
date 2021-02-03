#include <stdio.h>
extern "C"{
	NTSYSAPI
	DWORD
	NTAPI
	XexGetModuleHandle(
		IN		PSZ moduleName,
		IN OUT	PHANDLE hand
		); 

	NTSYSAPI
	DWORD
	NTAPI
	XexGetProcedureAddress(
		IN		HANDLE hand,
		IN		DWORD dwOrdinal,
		IN		PVOID Address
		);

	VOID XapiThreadStartup(
		IN		VOID (__cdecl *StartRoutine)(VOID *),
		IN		PVOID StartContext,
		IN		DWORD dwExitCode
	    );

	NTSYSAPI
	DWORD
	NTAPI
	ExCreateThread(
		IN		PHANDLE pHandle,
		IN		DWORD dwStackSize,
		IN		LPDWORD lpThreadId,
		IN		PVOID apiThreadStartup,
		IN		LPTHREAD_START_ROUTINE lpStartAddress,
		IN		LPVOID lpParameter,
		IN		DWORD dwCreationFlagsMod
	    );
}

UINT32 (*XamGetCurrentTitleId)(void);

DWORD ResolveFunct(PCHAR modname, DWORD ord)
{
	HANDLE hand;
	DWORD ret=0, Ptr2=0;
	ret = XexGetModuleHandle(modname, &hand); 
	if(ret == 0){
		ret = XexGetProcedureAddress(hand, ord, &Ptr2 );
		if(Ptr2 != 0)
			return Ptr2;
	}
	return 0;
}

#pragma once

typedef long							NTSTATUS;
#define NT_EXTRACT_ST(Status)			((((ULONG)(Status)) >> 30)& 0x3)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          (NT_EXTRACT_ST(Status) == 1)
#define NT_WARNING(Status)              (NT_EXTRACT_ST(Status) == 2)
#define NT_ERROR(Status)                (NT_EXTRACT_ST(Status) == 3)

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _EX_TITLE_TERMINATE_REGISTRATION {
	void*	   NotificationRoutine;
	DWORD	   Priority;
	LIST_ENTRY ListEntry;
} EX_TITLE_TERMINATE_REGISTRATION, *PEX_TITLE_TERMINATE_REGISTRATION;

typedef struct _XEX_IMPORT_DESCRIPTOR {
   DWORD Size;
   DWORD NameTableSize;
   DWORD ModuleCount;
} XEX_IMPORT_DESCRIPTOR, *PXEX_IMPORT_DESCRIPTOR;

typedef struct _HV_IMAGE_IMPORT_TABLE {
   BYTE  NextImportDigest[0x14];
   DWORD ModuleNumber;
   DWORD Version[0x02];
   BYTE  Unused;
   BYTE  ModuleIndex;
   WORD  ImportCount;
} HV_IMAGE_IMPORT_TABLE, *PHV_IMAGE_IMPORT_TABLE;

typedef struct _XEX_IMPORT_TABLE {
   DWORD                 TableSize;
   HV_IMAGE_IMPORT_TABLE ImportTable;
} XEX_IMPORT_TABLE, *PXEX_IMPORT_TABLE;

typedef struct _LDR_DATA_TABLE_ENTRY { 
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InClosureOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	VOID*          NtHeadersBase;
	VOID*          ImageBase;
	DWORD          SizeOfNtImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD          Flags;
	DWORD          SizeOfFullImage;
	VOID*          EntryPoint;
	WORD           LoadCount;
	WORD           ModuleIndex;
	VOID*          DllBaseOriginal;
	DWORD          CheckSum;
	DWORD          ModuleLoadFlags;
	DWORD          TimeDateStamp;
	VOID*          LoadedImports;
	VOID*          XexHeaderBase;
	union {
		ANSI_STRING               LoadFileName;
		struct {
			_LDR_DATA_TABLE_ENTRY* ClosureRoot;
			_LDR_DATA_TABLE_ENTRY* TraversalParent;
		} asEntry;
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _XBOX_HARDWARE_INFO {
	DWORD Flags;
	BYTE  NumberOfProcessors;
	BYTE  PCIBridgeRevisionID;
	BYTE  Reserved[6];
	WORD  BldrMagic;
	WORD  BldrFlags;
} XBOX_HARDWARE_INFO, *PXBOX_HARDWARE_INFO;

typedef struct _KERNEL_VERSION {
	WORD Major;
	WORD Minor;
	WORD Build;
	BYTE ApprovalType;
	BYTE QFE;
} KERNEL_VERSION, *PKERNEL_VERSION;

// Valid values for the Attributes field
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

typedef struct _OBJECT_ATTRIBUTES {
    HANDLE		 RootDirectory;
	PANSI_STRING ObjectName;
    ULONG		 Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// object type strings
#define OBJ_TYP_SYMBLINK	0x626d7953
#define OBJ_TYP_DIRECTORY	0x65726944
#define OBJ_TYP_DEVICE		0x69766544
#define OBJ_TYP_EVENT       0x76657645
#define OBJ_TYP_DEBUG       0x63706d64

typedef struct _OBJECT_DIRECTORY_INFORMATION{
	ANSI_STRING Name;
	DWORD		Type;
	CHAR		NameEx[MAX_PATH];
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID	 Pointer;
    } st;
    ULONG_PTR	 Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
);

typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG		  NextEntryOffset; 
	ULONG		  FileIndex; 
	LARGE_INTEGER CreationTime; 
	LARGE_INTEGER LastAccessTime; 
	LARGE_INTEGER LastWriteTime; 
	LARGE_INTEGER ChangeTime; 
	LARGE_INTEGER EndOfFile; 
	LARGE_INTEGER AllocationSize; 
	ULONG		  FileAttributes; 
	ULONG		  FileNameLength; 
	CHAR		  FileName[MAX_PATH];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

EXTERN_C {

	extern XBOX_HARDWARE_INFO*	  XboxHardwareInfo;
	extern KERNEL_VERSION*		  XboxKrnlVersion;
	extern PLDR_DATA_TABLE_ENTRY* XexExecutableModuleHandle;

	void ExRegisterTitleTerminateNotification(PEX_TITLE_TERMINATE_REGISTRATION, BOOL);

	void RtlInitAnsiString(PANSI_STRING DestinationString, const char* SourceString);

	void*	RtlImageXexHeaderField(void* XexHeaderBase, DWORD Key);
	HRESULT XexStartExecutable(FARPROC TitleProcessInitThreadProc);
	BOOL	XexCheckExecutablePrivilege(DWORD Privilege);

	DWORD ExGetXConfigSetting(WORD categoryNum, WORD settingNum, 
		BYTE* outputBuff, DWORD outputBuffSize, WORD* settingSize);

	DWORD ExSetXConfigSetting(WORD dwCategory, WORD dwSetting, PVOID pBuffer, WORD szSetting);

	DWORD XeKeysHmacSha(DWORD keyNum,
		BYTE* input1, DWORD input1Size,
		BYTE* input2, DWORD input2Size,
		BYTE* input3, DWORD input3Size,
		BYTE* digest, DWORD digestSize
		);

	NTSTATUS ObCreateSymbolicLink(PANSI_STRING, PANSI_STRING);
	NTSTATUS ObDeleteSymbolicLink(PANSI_STRING);
	NTSTATUS NtOpenSymbolicLinkObject(PHANDLE LinkHandle, POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle, PANSI_STRING LinkTarget, PULONG ReturnedLength);
	NTSTATUS NtClose(HANDLE Handle);

	NTSTATUS XeKeysGetKey(DWORD KeyNum, void* KeyBuffer, DWORD* KeySize);

	BOOL MmIsAddressValid(unsigned __int64 Address);

	void HalReturnToFirmware(DWORD);

	NTSTATUS NtCreateFile(HANDLE* FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, 
		ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions);

	NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions); 

	NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, PANSI_STRING FileMask, DWORD Unkn);

	NTSTATUS NtOpenDirectoryObject(PHANDLE DirectoryHandle, POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, 
		BOOLEAN ReturnSingleEntry, PULONG Context, PULONG ReturnLength);

	NTSTATUS NtClose(HANDLE Handle);

	UINT64 MmGetPhysicalAddress(UINT64 Address);

	UINT64
	NTAPI 
	XeKeysExecute(
		UINT64		pBuffer, 
		DWORD		dwFileSize, 
		UINT64		Input1, 
		UINT64		Input2, 
		UINT64		Input3, 
		UINT64		Input4
		); 	
}

#define SetMemory(Dest, Source, Size) { memcpy(Dest, Source, Size); }

VOID PatchInJump(DWORD* Address, DWORD Destination, BOOL Linked)
{
	DWORD setData[4];
	if(Destination & 0x8000)
		setData[0] = 0x3D600000 + (((Destination >> 16) & 0xFFFF) + 1);
	else
		setData[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF);
	setData[1] = 0x396B0000 + (Destination & 0xFFFF);
	setData[2] = 0x7D6903A6;
	if(Linked)
		setData[3] = 0x4E800421;
	else
		setData[3] = 0x4E800420;
	SetMemory(Address, setData, 16);
}

FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal) 
{
	HMODULE mHandle = GetModuleHandle(ModuleName);
	if(mHandle == NULL)
		return NULL;
	return GetProcAddress(mHandle, (LPCSTR)Ordinal);
}
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) 
{
	DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
	if(address == NULL)
		return S_FALSE;
	VOID* headerBase = Module->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)
		RtlImageXexHeaderField(headerBase, 0x000103FF);
	if(importDesc == NULL)
		return S_FALSE;
	DWORD result = 2; 
	CHAR* stringTable = (CHAR*)(importDesc + 1);
	PXEX_IMPORT_TABLE importTable = (PXEX_IMPORT_TABLE)(stringTable + importDesc->NameTableSize);
	for(DWORD x = 0; x < importDesc->ModuleCount; x++) 
	{
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for(DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) 
		{
			DWORD value = *((DWORD*)importAdd[y]);
			if(value == address) 
			{
				SetMemory((DWORD*)importAdd[y], &PatchAddress, 4);
				DWORD newCode[4];
				PatchInJump(newCode, PatchAddress, FALSE);
				SetMemory((DWORD*)importAdd[y + 1], newCode, 16);
				result = S_OK;
			}
		}
		importTable = (PXEX_IMPORT_TABLE)(((BYTE*)importTable) + importTable->TableSize);
	}
	return result;
}
DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) 
{
	LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
	if(moduleHandle == NULL) 
		return S_FALSE;
	return PatchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
}
DWORD PatchModuleImport(CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) 
{
	return PatchModuleImport(*XexExecutableModuleHandle, ImportedModuleName, Ordinal, PatchAddress);
}

HRESULT SetCodeBranch(DWORD SourceAddress, DWORD TargetAddress) 
{
	DWORD code = 0x4C000001 + (TargetAddress - SourceAddress);
	SetMemory((VOID*)SourceAddress, &code, 4);
	return S_OK;
}

HRESULT CreateSymbolicLink(CHAR* szDrive, CHAR* szDeviceName, BOOL System) 
{
	CHAR szDestinationDrive[MAX_PATH];
	if(System)
		sprintf_s(szDestinationDrive, MAX_PATH, "\\System??\\%s", szDrive);
	else
		sprintf_s(szDestinationDrive, MAX_PATH, "\\??\\%s", szDrive);
	ANSI_STRING linkname, devicename;
	RtlInitAnsiString(&linkname, szDestinationDrive);
	RtlInitAnsiString(&devicename, szDeviceName);
	NTSTATUS status = ObCreateSymbolicLink(&linkname, &devicename);
	if (status >= 0)
		return S_OK;
	return S_FALSE;
}

HRESULT DeleteSymbolicLink(CHAR* szDrive, BOOL System) 
{
	CHAR szDestinationDrive[MAX_PATH];
	if(System)
		sprintf_s(szDestinationDrive, MAX_PATH, "\\System??\\%s", szDrive);
	else
		sprintf_s(szDestinationDrive, MAX_PATH, "\\??\\%s", szDrive);
	ANSI_STRING linkname;
	RtlInitAnsiString(&linkname, szDestinationDrive);
	NTSTATUS status = ObDeleteSymbolicLink(&linkname);
	if (status >= 0)
		return S_OK;
	return S_FALSE;
}