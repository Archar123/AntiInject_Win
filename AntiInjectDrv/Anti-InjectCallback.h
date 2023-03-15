#pragma once
#include "Anti-InjectBase.h"

EXTERN_C

VOID
AntiInjectLoadImageRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

VOID
AntiInjectCreateProcessNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);


