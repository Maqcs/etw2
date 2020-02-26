#include "etwmon.h"
#include <guiddef.h>
#include <stdlib.h>
#include <stdio.h>

typedef GUID *PGUID;
#define  NOTHING

ULONG NTAPI EtpEtwBufferCallback( _In_ PEVENT_TRACE_LOGFILE Buffer);
VOID NTAPI EtpEtwEventCallback(_In_ PEVENT_RECORD EventRecord);
DWORD WINAPI EtpEtwMonitorThreadStart(_In_ PVOID Parameter);

ULONG EtpStopEtwRundownSession(VOID);

ULONG NTAPI EtpRundownEtwBufferCallback(_In_ PEVENT_TRACE_LOGFILE Buffer);

VOID NTAPI EtpRundownEtwEventCallback(_In_ PEVENT_RECORD EventRecord);

DWORD WINAPI EtpRundownEtwMonitorThreadStart(_In_ PVOID Parameter);

static GUID ProcessHackerGuid = { 0x1288c53b, 0xaf35, 0x481b, { 0xb6, 0xb5, 0xa0, 0x5c, 0x39, 0x87, 0x2e, 0xd } };
static GUID SystemTraceControlGuid_I = { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };
static GUID KernelRundownGuid_I = { 0x3b9c9951, 0x3480, 0x4220, { 0x93, 0x77, 0x9c, 0x8e, 0x51, 0x84, 0xf5, 0xcd } };
static GUID DiskIoGuid_I = { 0x3d6fa8d4, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
static GUID FileIoGuid_I = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
static GUID TcpIpGuid_I = { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
static GUID UdpIpGuid_I = { 0xbf3a50c5, 0xa9c9, 0x4988, { 0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80 } };

// ETW tracing layer

BOOLEAN EtEtwEnabled;
static UNICODE_STRING EtpSharedKernelLoggerName = RTL_CONSTANT_STRING(KERNEL_LOGGER_NAME);
static UNICODE_STRING EtpPrivateKernelLoggerName = RTL_CONSTANT_STRING(L"PhEtKernelLogger");
static TRACEHANDLE EtpSessionHandle;
static PUNICODE_STRING EtpActualKernelLoggerName;
static PGUID EtpActualSessionGuid;
static PEVENT_TRACE_PROPERTIES EtpTraceProperties;
static BOOLEAN EtpEtwActive;
static BOOLEAN EtpStartedSession;
static BOOLEAN EtpEtwExiting;
static HANDLE EtpEtwMonitorThreadHandle;

// ETW rundown layer

static UNICODE_STRING EtpRundownLoggerName = RTL_CONSTANT_STRING(L"PhEtRundownLogger");
static TRACEHANDLE EtpRundownSessionHandle;
static PEVENT_TRACE_PROPERTIES EtpRundownTraceProperties;
static BOOLEAN EtpRundownActive;
static HANDLE EtpRundownEtwMonitorThreadHandle;

VOID EtEtwMonitorInitialization(
    VOID
    )
{
	EtStartEtwSession();
	if (EtEtwEnabled)
	{
		
		EtpEtwMonitorThreadHandle = CreateThread(NULL, 0, EtpEtwMonitorThreadStart, NULL, 0, NULL);
	}
}

VOID EtEtwMonitorUninitialization(VOID)
{
    if (EtEtwEnabled)
    {
        EtpEtwExiting = TRUE;
        EtStopEtwSession();
    }

    if (EtpRundownActive)
    {
        EtpStopEtwRundownSession();
    }
}

BOOL SetPrivilege(LPCTSTR a_Name, BOOL a_Enable)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(NULL, a_Name, &luid))
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = a_Enable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

VOID EtStartEtwSession(VOID)
{
    ULONG result;
    ULONG bufferSize;

	//if (WindowsVersion >= WINDOWS_8)
	//{
	//	EtpActualKernelLoggerName = &EtpPrivateKernelLoggerName;
	//	EtpActualSessionGuid = &ProcessHackerGuid;
	//}
	//else
	//{
		EtpActualKernelLoggerName = &EtpSharedKernelLoggerName;
		EtpActualSessionGuid = &SystemTraceControlGuid_I;
	//}

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + EtpActualKernelLoggerName->Length + sizeof(WCHAR);

    if (!EtpTraceProperties)
        EtpTraceProperties = malloc(bufferSize);

    memset(EtpTraceProperties, 0, sizeof(EVENT_TRACE_PROPERTIES));

    EtpTraceProperties->Wnode.BufferSize = bufferSize;
    EtpTraceProperties->Wnode.Guid = *EtpActualSessionGuid;
    EtpTraceProperties->Wnode.ClientContext = 1;
    EtpTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    //EtpTraceProperties->MinimumBuffers = 1;
    EtpTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    EtpTraceProperties->FlushTimer = 1;
    EtpTraceProperties->EnableFlags = EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO;
    EtpTraceProperties->LogFileNameOffset = 0;
    EtpTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // if (WindowsVersion >= WINDOWS_8)
	//		EtpTraceProperties->LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;

	SetPrivilege(SE_SYSTEM_PROFILE_NAME, TRUE);

	// 注册和启动一个事件跟踪会话
    result = StartTrace(&EtpSessionHandle,  // 返回会话句柄
		EtpActualKernelLoggerName->Buffer,  // 会话名
		EtpTraceProperties); // 会话参数

    if (result == ERROR_SUCCESS)
    {
        EtEtwEnabled = TRUE;
        EtpEtwActive = TRUE;
        EtpStartedSession = TRUE;
    }
    else if (result == ERROR_ALREADY_EXISTS)
    {
        EtEtwEnabled = TRUE;
        EtpEtwActive = TRUE;
        EtpStartedSession = FALSE;
        // The session already exists.
		//result = ControlTrace(0, EtpActualKernelLoggerName->Buffer, EtpTraceProperties, EVENT_TRACE_CONTROL_UPDATE);
    }
    else
    {
        EtpEtwActive = FALSE;
        EtpStartedSession = FALSE;
    }
}

ULONG EtpControlEtwSession(
    _In_ ULONG ControlCode
    )
{
    // If we have a session handle, we use that instead of the logger name.
    EtpTraceProperties->LogFileNameOffset = 0; // make sure it is 0, otherwise ControlTrace crashes

    return ControlTrace( 
        EtpStartedSession ? EtpSessionHandle : 0,
        EtpStartedSession ? NULL : EtpActualKernelLoggerName->Buffer,
        EtpTraceProperties,
        ControlCode
        );
}

VOID EtStopEtwSession()
{
    if (EtEtwEnabled)
        EtpControlEtwSession(EVENT_TRACE_CONTROL_STOP);
}

VOID EtFlushEtwSession()
{
    if (EtEtwEnabled)
        EtpControlEtwSession(EVENT_TRACE_CONTROL_FLUSH);
}

ULONG NTAPI EtpEtwBufferCallback(_In_ PEVENT_TRACE_LOGFILE Buffer)
{
    return !EtpEtwExiting;
}

// EtpEtwEventCallback 跟踪事件回调
VOID NTAPI EtpEtwEventCallback(_In_ PEVENT_RECORD EventRecord)
{
    if (memcmp(&EventRecord->EventHeader.ProviderId, &DiskIoGuid_I, sizeof(GUID)) == 0)
    {
        // DiskIo

        ET_ETW_DISK_EVENT diskEvent;

        memset(&diskEvent, 0, sizeof(ET_ETW_DISK_EVENT));
        diskEvent.Type = -1;

        switch (EventRecord->EventHeader.EventDescriptor.Opcode)
        {
        //case EVENT_TRACE_TYPE_IO_READ:
        //    diskEvent.Type = EtEtwDiskReadType;

        case EVENT_TRACE_TYPE_IO_WRITE:
            diskEvent.Type = EtEtwDiskWriteType;


			DiskIo_TypeGroup1 *data = EventRecord->UserData;

			//if (WindowsVersion >= WINDOWS_8)
			//{
			//	diskEvent.ClientId.UniqueThread = UlongToHandle(data->IssuingThreadId);
			//	diskEvent.ClientId.UniqueProcess = EtThreadIdToProcessId(diskEvent.ClientId.UniqueThread);
			//}
			//else
			//{
			if (EventRecord->EventHeader.ProcessId != -1)
			{
				diskEvent.ClientId.UniqueProcess = UlongToHandle(EventRecord->EventHeader.ProcessId);
				diskEvent.ClientId.UniqueThread = UlongToHandle(EventRecord->EventHeader.ThreadId);
			}
			//}

			diskEvent.IrpFlags = data->IrpFlags;
			diskEvent.TransferSize = data->TransferSize;
			diskEvent.FileObject = (PVOID)data->FileObject;
			diskEvent.HighResResponseTime = data->HighResResponseTime;

			wprintf(L"Process[%d] FileObject[%u]\n", EventRecord->EventHeader.ProcessId, data->FileObject);
			//EtProcessDiskEvent(&diskEvent);
			//EtDiskProcessDiskEvent(&diskEvent);
            break;
        default:
            break;
        }

    }
    else if (memcmp(&EventRecord->EventHeader.ProviderId, &FileIoGuid_I, sizeof(GUID)) == 0)
    {
        // FileIo

        ET_ETW_FILE_EVENT fileEvent;

        memset(&fileEvent, 0, sizeof(ET_ETW_FILE_EVENT));
        fileEvent.Type = -1;

        switch (EventRecord->EventHeader.EventDescriptor.Opcode)
        {
        case 0: // Name
            fileEvent.Type = EtEtwFileNameType;
            break;
        case 32: // FileCreate
            fileEvent.Type = EtEtwFileCreateType;
            break;
        case 35: // FileDelete
            fileEvent.Type = EtEtwFileDeleteType;
            break;
        default:
            break;
        }

        if (fileEvent.Type != -1)
        {
			//if (PhIsExecutingInWow64())
			//{
   //             FileIo_Name_Wow64 *dataWow64 = EventRecord->UserData;

   //             fileEvent.FileObject = (PVOID)dataWow64->FileObject;
   //             PhInitializeStringRef(&fileEvent.FileName, dataWow64->FileName);
   //         }
			//else
			//{
				FileIo_Name *data = EventRecord->UserData;

				fileEvent.FileObject = (PVOID)data->FileObject;
				//PhInitializeStringRef(&fileEvent.FileName, data->FileName);

				fileEvent.FileName.Length = wcslen(data->FileName) * sizeof(WCHAR);
				fileEvent.FileName.Buffer = &(data->FileName[0]);

				wprintf(L"FileName[%s] FileObject[%u]\n", fileEvent.FileName.Buffer, fileEvent.FileObject);


			//}

            //EtDiskProcessFileEvent(&fileEvent);
        }
    }
}

DWORD WINAPI EtpEtwMonitorThreadStart(_In_ PVOID Parameter)
{
    ULONG result;
    EVENT_TRACE_LOGFILE logFile; // 跟踪会话
    TRACEHANDLE traceHandle;

    // See comment in EtEtwProcessesUpdatedCallback.
    //if (WindowsVersion >= WINDOWS_8)
    //    EtUpdateProcessInformation();

    memset(&logFile, 0, sizeof(EVENT_TRACE_LOGFILE));
	//  两种模式，1. 使用日志文件的中事件， 将LogFileName设置为日志文件的名称
	// 2.使用实时会话中的事件，将LoggerName成员设置为会话名称
    logFile.LoggerName = EtpActualKernelLoggerName->Buffer; // 指定会话名（这里使用系统默认的NT Kernel Log）
    
	// 实时事件记录
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

    logFile.BufferCallback = EtpEtwBufferCallback; // 接受并处理有关当前缓冲区的摘要信息
    logFile.EventRecordCallback = EtpEtwEventCallback; // 接受并处理所有事件（包括标头事件）

    while (TRUE)
    {
        result = ERROR_SUCCESS;
        traceHandle = OpenTrace(&logFile); // 打开一个跟踪会话

        if (traceHandle != INVALID_PROCESSTRACE_HANDLE)
        {
			// 传递OpenTrace的句柄给ProcessTrace
			// ProcessTrace 按照时间顺序把日志传递给会话的回调 
            while (!EtpEtwExiting && 
				(result = ProcessTrace(&traceHandle, 1, NULL, NULL)) /*（启用跟踪会话）*/
				== ERROR_SUCCESS)
                NOTHING;

            CloseTrace(traceHandle);
        }

        if (EtpEtwExiting)
            break;

        if (result == ERROR_WMI_INSTANCE_NOT_FOUND)
        {
            // The session was stopped by another program. Try to start it again.
            EtStartEtwSession();
        }

        // Some error occurred, so sleep for a while before trying again.
        // Don't sleep if we just successfully started a session, though.
		if (!EtpEtwActive)
			//PhDelayExecution(250);
			Sleep(250);
    }

    return 0;
}

// EtStartEtwRundown 关闭跟踪事件
ULONG EtStartEtwRundown(VOID)
{
    ULONG result;
    ULONG bufferSize;

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + EtpRundownLoggerName.Length + sizeof(WCHAR);

    if (!EtpRundownTraceProperties)
        EtpRundownTraceProperties = malloc(bufferSize);

    memset(EtpRundownTraceProperties, 0, sizeof(EVENT_TRACE_PROPERTIES));

    EtpRundownTraceProperties->Wnode.BufferSize = bufferSize;
    EtpRundownTraceProperties->Wnode.ClientContext = 1;
    EtpRundownTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    EtpRundownTraceProperties->MinimumBuffers = 1;
    EtpRundownTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    EtpRundownTraceProperties->FlushTimer = 1;
    EtpRundownTraceProperties->LogFileNameOffset = 0;
    EtpRundownTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    result = StartTrace(&EtpRundownSessionHandle, EtpRundownLoggerName.Buffer, EtpRundownTraceProperties);

    if (result == ERROR_ALREADY_EXISTS)
    {
        EtpStopEtwRundownSession();
        // ControlTrace (called from EtpStopEtwRundownSession) screws up the structure.
        EtpRundownTraceProperties->Wnode.BufferSize = bufferSize;
        EtpRundownTraceProperties->LogFileNameOffset = 0;
        EtpRundownTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		
		// 启用一个已存在的跟踪会话
        result = StartTrace(&EtpRundownSessionHandle, EtpRundownLoggerName.Buffer, EtpRundownTraceProperties);
    }

    if (result != ERROR_SUCCESS)
        return result;

    result = EnableTraceEx(
		&KernelRundownGuid_I, 
		NULL, 
		EtpRundownSessionHandle, 
		1, 
		0, 
		0x10, 
		0, 
		0, 
		NULL);

    if (result != ERROR_SUCCESS)
    {
        EtpStopEtwRundownSession();
        return result;
    }

    EtpRundownActive = TRUE;
    EtpRundownEtwMonitorThreadHandle = CreateThread(NULL, 0, EtpRundownEtwMonitorThreadStart, NULL, 0, NULL);
    return result;
}

ULONG EtpStopEtwRundownSession(
    VOID
    )
{
    EtpRundownTraceProperties->LogFileNameOffset = 0;
    return ControlTrace(0, EtpRundownLoggerName.Buffer, EtpRundownTraceProperties, EVENT_TRACE_CONTROL_STOP);
}

ULONG NTAPI EtpRundownEtwBufferCallback(
    _In_ PEVENT_TRACE_LOGFILE Buffer
    )
{
    return !EtpEtwExiting;
}

VOID NTAPI EtpRundownEtwEventCallback(
    _In_ PEVENT_RECORD EventRecord
    )
{
    // TODO: Find a way to call CloseTrace when the enumeration finishes so we can
    // stop the trace cleanly.

    if (memcmp(&EventRecord->EventHeader.ProviderId, &FileIoGuid_I, sizeof(GUID)) == 0)
    {
        // FileIo

        ET_ETW_FILE_EVENT fileEvent;

        memset(&fileEvent, 0, sizeof(ET_ETW_FILE_EVENT));
        fileEvent.Type = -1;

        switch (EventRecord->EventHeader.EventDescriptor.Opcode)
        {
        case 36: // FileRundown
            fileEvent.Type = EtEtwFileRundownType;
            break;
        default:
            break;
        }

        if (fileEvent.Type != -1)
        {
            //if (PhIsExecutingInWow64())
            //{
                FileIo_Name_Wow64 *dataWow64 = EventRecord->UserData;

                fileEvent.FileObject = (PVOID)dataWow64->FileObject;
                //PhInitializeStringRef(&fileEvent.FileName, dataWow64->FileName);
            //}
            //else
            //{
            //    FileIo_Name *data = EventRecord->UserData;

            //    fileEvent.FileObject = (PVOID)data->FileObject;
            //    //PhInitializeStringRef(&fileEvent.FileName, data->FileName);
            //}

            //EtDiskProcessFileEvent(&fileEvent);
        }
    }
}

DWORD WINAPI EtpRundownEtwMonitorThreadStart(_In_ PVOID Parameter)
{
    EVENT_TRACE_LOGFILE logFile;
    TRACEHANDLE traceHandle;

    memset(&logFile, 0, sizeof(EVENT_TRACE_LOGFILE));
    logFile.LoggerName = EtpRundownLoggerName.Buffer;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.BufferCallback = EtpRundownEtwBufferCallback;
    logFile.EventRecordCallback = EtpRundownEtwEventCallback;
    logFile.Context = &traceHandle;

    traceHandle = OpenTrace(&logFile);

    if (traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        ProcessTrace(&traceHandle, 1, NULL, NULL);

        if (traceHandle != 0)
            CloseTrace(traceHandle);
    }

    CloseHandle(EtpRundownEtwMonitorThreadHandle);
    EtpRundownEtwMonitorThreadHandle = NULL;

    return 0;
}
