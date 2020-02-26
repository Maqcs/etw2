#ifndef ETWMON_H
#define ETWMON_H


#include <windows.h>
#include <evntcons.h>

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }

typedef struct _PH_STRINGREF
{
	/** The length, in bytes, of the string. */
	SIZE_T Length;
	/** The buffer containing the contents of the string. */
	PWCH Buffer;
} PH_STRINGREF, *PPH_STRINGREF;

typedef struct
{
    ULONG DiskNumber;
    ULONG IrpFlags;
    ULONG TransferSize;
    ULONG ResponseTime;
    ULONG64 ByteOffset;
    ULONG_PTR FileObject;
    ULONG_PTR Irp;
    ULONG64 HighResResponseTime;
    ULONG IssuingThreadId; // since WIN8 (ETW_DISKIO_READWRITE_V3)
} DiskIo_TypeGroup1;

typedef struct
{
    ULONG_PTR FileObject;
    WCHAR FileName[1];
} FileIo_Name;

typedef struct
{
    ULONGLONG FileObject;
    WCHAR FileName[1];
} FileIo_Name_Wow64;


// etwmon

VOID EtEtwMonitorInitialization(
    VOID
    );

VOID EtEtwMonitorUninitialization(
    VOID
    );

VOID EtStartEtwSession(
    VOID
    );

VOID EtStopEtwSession(
    VOID
    );

VOID EtFlushEtwSession(
    VOID
    );

ULONG EtStartEtwRundown(
    VOID
    );

// etwstat

typedef enum _ET_ETW_EVENT_TYPE
{
    EtEtwDiskReadType = 1,
    EtEtwDiskWriteType,
    EtEtwFileNameType,
    EtEtwFileCreateType,
    EtEtwFileDeleteType,
    EtEtwFileRundownType,
    EtEtwNetworkReceiveType,
    EtEtwNetworkSendType
} ET_ETW_EVENT_TYPE;

typedef struct _ET_ETW_DISK_EVENT
{
    ET_ETW_EVENT_TYPE Type;
    CLIENT_ID ClientId;
    ULONG IrpFlags;
    ULONG TransferSize;
    PVOID FileObject;
    ULONG64 HighResResponseTime;
} ET_ETW_DISK_EVENT, *PET_ETW_DISK_EVENT;

typedef struct _ET_ETW_FILE_EVENT
{
    ET_ETW_EVENT_TYPE Type;
    PVOID FileObject;
    PH_STRINGREF FileName;
} ET_ETW_FILE_EVENT, *PET_ETW_FILE_EVENT;


// etwstat

VOID EtProcessDiskEvent(
    _In_ PET_ETW_DISK_EVENT Event
    );


VOID EtUpdateProcessInformation(
    VOID
    );

HANDLE EtThreadIdToProcessId(
    _In_ HANDLE ThreadId
    );

// etwdisk

VOID EtDiskProcessDiskEvent(
    _In_ PET_ETW_DISK_EVENT Event
    );

VOID EtDiskProcessFileEvent(
    _In_ PET_ETW_FILE_EVENT Event
    );

#endif


//VOID
//PhInitializeStringRef(
//	_Out_ PPH_STRINGREF String,
//	_In_ PWSTR Buffer
//)
//{
//	String->Length = wcslen(Buffer) * sizeof(WCHAR);
//	String->Buffer = Buffer;
//}