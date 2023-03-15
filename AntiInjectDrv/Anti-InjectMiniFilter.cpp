#include "Anti-InjectMiniFilter.h"
#include <dontuse.h>
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

extern GLOBAL_DATA g_Global_Data;

ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))
//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      AntiInjectFltAcquireSectionSyncPreRoutine,
      AntiInjectFltAcquireSectionSyncPostRoutine },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    (PFLT_FILTER_UNLOAD_CALLBACK)UnloadMiniFilter,

    NULL,                    //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,            //  InstanceTeardownStart
    NULL,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


NTSTATUS
InitMiniFilter (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntiInject!DriverEntry: Entered\n") );

    //  Register with FltMgr to tell it our callback routines
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                (PFLT_FILTER *)&g_Global_Data.m_MFilterHandle );

    if (NT_SUCCESS( status )) 
    {
        status = FltStartFiltering( (PFLT_FILTER)g_Global_Data.m_MFilterHandle );

        if (!NT_SUCCESS( status )) 
        {
            FltUnregisterFilter((PFLT_FILTER)g_Global_Data.m_MFilterHandle);
        }
    }
    
    return status;
}

NTSTATUS
UnloadMiniFilter (
    _In_ ULONG Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntiInject!AntiInjectUnload: Entered\n") );

    if ((PFLT_FILTER)g_Global_Data.m_MFilterHandle &&
        g_Global_Data.m_IsInitMiniFilter)
    {
        FltUnregisterFilter((PFLT_FILTER)g_Global_Data.m_MFilterHandle);
        g_Global_Data.m_IsInitMiniFilter = FALSE;
    }

    return STATUS_SUCCESS;
}



//
FLT_PREOP_CALLBACK_STATUS
AntiInjectFltAcquireSectionSyncPreRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FLT_FILE_NAME_INFORMATION* pFileInfo = NULL;
    PEPROCESS EprocessOperation = NULL;
    HANDLE ProcessId = NULL;
    DECLARE_UNICODE_STRING_SIZE(uOperationProcessPath, MAX_PATH);
    WCHAR* pTargetImageName = NULL;
    UNICODE_STRING uniStr = { 0x00 };
    ULONG_PTR dwRet = 0;
    LARGE_INTEGER Offset = { 0x00 };
    ULONG dwBufferSize = 0;
    PUCHAR pTargetImageBuffer = NULL;
    BOOLEAN bIs = FALSE;
    KAPC_STATE kApc = { 0x00 };

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pFileInfo);
    if (!NT_SUCCESS(status))
        goto finish;

    ProcessId = (HANDLE)FltGetRequestorProcessId(Data);

    status = PsLookupProcessByProcessId(ProcessId, &EprocessOperation);
    if (!NT_SUCCESS(status))
        goto finish;

    __try
    {
        KeStackAttachProcess(EprocessOperation, &kApc);

        status = KrnlGetProcessName(EprocessOperation, &uOperationProcessPath);
    }
    __finally
    {
        KeUnstackDetachProcess(&kApc);
    }

    if (!NT_SUCCESS(status))
        goto finish;

    KrnlGetImageNameByPath(&pFileInfo->Name, &pTargetImageName, &dwRet);

    pTargetImageBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, 0x1000, 'khC');
    if (!pTargetImageBuffer)
        goto finish;

    status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &Offset, 0x1000, pTargetImageBuffer, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &dwBufferSize, NULL, NULL);
    if (!NT_SUCCESS(status))
        goto finish;
    if (!KrnlCheckPE(pTargetImageBuffer, 0x1000))
        goto finish;

    RtlInitUnicodeString(&uniStr, pTargetImageName);
    LockList(&g_Global_Data.m_ProtectProcessListLock);

    if (KrnlIsProtectName(&uniStr, &g_Global_Data.m_ProtectProcessListHeader) &&
        Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection
        )
    {
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
        if ((Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection & PAGE_EXECUTE) == 0)
            goto finish;
        AkrOsPrint("%wZ Create Section With %ws!\n", uOperationProcessPath, pTargetImageName);

        LockList(&g_Global_Data.m_WhiteListLock);
        if (!MatchBlackWhitelistByProcessName(&uOperationProcessPath, &g_Global_Data.m_WhiteListHeader))
        {
            bIs = TRUE;
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        UnlockList(&g_Global_Data.m_WhiteListLock);
    }
    else
    {
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
    }

finish:
    if (EprocessOperation)
        ObDereferenceObject(EprocessOperation);
    if (pFileInfo)
        FltReleaseFileNameInformation(pFileInfo);
    if (pTargetImageBuffer)
        ExFreePoolWithTag(pTargetImageBuffer, 0);
    if (bIs)
    {
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
AntiInjectFltAcquireSectionSyncPostRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}