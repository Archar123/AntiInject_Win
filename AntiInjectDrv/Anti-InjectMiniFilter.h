#pragma once
#include "Anti-InjectBase.h"

EXTERN_C
FLT_PREOP_CALLBACK_STATUS
AntiInjectFltAcquireSectionSyncPreRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

EXTERN_C
FLT_POSTOP_CALLBACK_STATUS
AntiInjectFltAcquireSectionSyncPostRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);


EXTERN_C  
NTSTATUS
InitMiniFilter(
    _In_ PDRIVER_OBJECT DriverObject
);

EXTERN_C
NTSTATUS
UnloadMiniFilter(
    _In_ ULONG Flags
);