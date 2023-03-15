#include "Anti-InjectCallback.h"
#include "NtosApi.h"

extern GLOBAL_DATA g_Global_Data;

NTSTATUS Hook_DriverEntryPointer(PDRIVER_OBJECT* pDriverObject, UNICODE_STRING* pRegPath)
{
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegPath);

    AkrOsPrint("!!!Blocked Driver! %ws", pRegPath->Buffer);
    return STATUS_UNSUCCESSFUL;
}

VOID
AntiInjectLoadImageRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,                
    _In_ PIMAGE_INFO ImageInfo
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PEPROCESS Process = NULL;
    DECLARE_UNICODE_STRING_SIZE(uCurrentProcessName, MAX_PATH);
    UNICODE_STRING uImageName = { 0x00 };
    WCHAR* szImageName = NULL;
    ULONG_PTR ImageNameSize = 0;
    IMAGE_DOS_HEADER* pDos = NULL;
    IMAGE_NT_HEADERS* pNt = NULL;
    PVOID ImageEntryPointer = NULL;
    PMDL pMdl = NULL;

    //For driverentry that overrides the target driver, 10 bytes is sufficient
    ULONG Size = 0x10;
    PVOID pNewMapVa = NULL;
    KAPC_STATE kApc = { 0x00 };
    wchar_t* pExeName = NULL;

    PROCESS_BASIC_INFORMATION ProcInfo = { 0x00 };
    ULONG dwInfoSize = 0;

    Status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &Process);
    if (!NT_SUCCESS(Status))
        goto ret;

    __try
    {
        KeStackAttachProcess(Process, &kApc);
        KrnlGetProcessName(Process, &uCurrentProcessName);

        Status = KrnlGetImageNameByPath(FullImageName, &szImageName, &ImageNameSize);
        if (!NT_SUCCESS(Status))
            __leave;
        
    }
    __finally
    {
        KeUnstackDetachProcess(&kApc);
    }

    RtlInitUnicodeString(&uImageName, szImageName);
    uImageName.Length = (USHORT)ImageNameSize;

    pDos = (IMAGE_DOS_HEADER*)ImageInfo->ImageBase;
    if (!MmIsAddressValid(pDos) || pDos->e_magic != IMAGE_DOS_SIGNATURE)
        goto ret;

    pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDos + pDos->e_lfanew);
    if (!MmIsAddressValid(pNt) || pNt->Signature != IMAGE_NT_SIGNATURE)
        goto ret;

    pExeName = wcschr(uImageName.Buffer, L'.');
    if (!pExeName)
        goto ret;

    //compare target driver With Black List
    LockList(&g_Global_Data.m_BlackListLock);
    if (MatchBlackWhitelistByProcessName(&uImageName, &g_Global_Data.m_BlackListHeader))
    {
        //Load .sys
        //if (wcscmp(pExeName, L".sys") == 0)
        if(ProcessId == (HANDLE)0)
        {
            if (pNt->OptionalHeader.AddressOfEntryPoint == 0)
            {
                pNt->OptionalHeader.AddressOfEntryPoint = pNt->OptionalHeader.BaseOfCode;
            }

            ImageEntryPointer = (PVOID)(ULONG_PTR)(pNt->OptionalHeader.ImageBase + pNt->OptionalHeader.AddressOfEntryPoint);
            
            if (!MmIsAddressValid(ImageEntryPointer) || ImageEntryPointer <= MM_SYSTEM_RANGE_START)
            {
                ImageEntryPointer = (PVOID)((ULONG_PTR)pDos + pNt->OptionalHeader.AddressOfEntryPoint);
                if (!MmIsAddressValid(ImageEntryPointer))
                    goto finish;
            }

            pNewMapVa = ImageEntryPointer;

            //Map the physical address to a new virtual address, and then write to that virtual address...
#if NTDDI_VERSION >= NTDDI_WIN8
            pMdl = IoAllocateMdl(ImageEntryPointer, Size, FALSE, FALSE, NULL);
            if (!pMdl)
                goto finish;
            
            MmProbeAndLockPages(pMdl, KernelMode, (LOCK_OPERATION)(IoReadAccess | IoWriteAccess | IoModifyAccess));
            
            __try
            {
                pNewMapVa = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
            }
            __finally
            {
                AkrOsPrint("MmMapLockedPagesSpecifyCache Fail!\n");
            }
            if (pNewMapVa)
            {
                //Override DriverEntry in the blacklist
                RtlCopyMemory(pNewMapVa, Hook_DriverEntryPointer, Size);
                MmUnmapLockedPages(pNewMapVa, pMdl);
            }

            IoFreeMdl(pMdl);
#else
            UNREFERENCED_PARAMETER(pMdl);
            if (pNewMapVa)
            {
                RtlCopyMemory(pNewMapVa, Hook_DriverEntryPointer, Size);
            }

#endif //NTDDI_VERSION >= NTDDI_WIN8
        }
        else if (wcscmp(pExeName, L".exe") == 0)
        {
            __try
            {
                KeStackAttachProcess(Process, &kApc);
                Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &ProcInfo, sizeof(PROCESS_BASIC_INFORMATION),&dwInfoSize);
                if (!NT_SUCCESS(Status))
                    __leave;

            }
            __finally
            {
                KeUnstackDetachProcess(&kApc);
            }
        }
    }
finish:
    UnlockList(&g_Global_Data.m_BlackListLock);

    //Load Dll
    //For loading DLLS, block loading if the target process is protected
    if ((pNt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
    {
        LockList(&g_Global_Data.m_ProtectProcessListLock);
        //if it is Protect Process
        if (KrnlIsProtectName(&uCurrentProcessName, &g_Global_Data.m_ProtectProcessListHeader))
        {
            //This is reserved for future use
        }
        UnlockList(&g_Global_Data.m_ProtectProcessListLock);
    }

ret:
    if(Process)
        ObDereferenceObject(Process);
    return;
}

VOID
AntiInjectCreateProcessNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PEPROCESS Eprocess = NULL;
    KAPC_STATE kApc = { 0x00 };
    DECLARE_UNICODE_STRING_SIZE(uCurrentProcessName, MAX_PATH);
    LIST_ENTRY* pEntry = NULL;
    ANTI_INJECT_PROTECT_PROCESS_DATA* pProtectData = NULL;
    
    if (Create == TRUE)
    {
        do 
        {
            Status = PsLookupProcessByProcessId(ProcessId, &Eprocess);
            if (!NT_SUCCESS(Status))
                return;

            __try
            {
                KeStackAttachProcess(Eprocess, &kApc);
                KrnlGetProcessName(Eprocess, &uCurrentProcessName);
                if (!NT_SUCCESS(Status))
                    __leave;

            }
            __finally
            {
                KeUnstackDetachProcess(&kApc);
            }

            LockList(&g_Global_Data.m_ProtectProcessListLock);
            if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
            {
                UnlockList(&g_Global_Data.m_ProtectProcessListLock);
                break;
            }

            pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;
            UnlockList(&g_Global_Data.m_ProtectProcessListLock);
            pProtectData = CONTAINING_RECORD(pEntry, ANTI_INJECT_PROTECT_PROCESS_DATA, m_Entry);
            if (!pProtectData || !MmIsAddressValid(pProtectData))
                break;

            //Find Protect.exe is Create...
            if (_wcsnicmp(uCurrentProcessName.Buffer, pProtectData->m_Name,wcslen(pProtectData->m_Name)) == 0)
            {
                //update Eprocess Pointer...
                pProtectData->m_Eprocess = Eprocess;
                //Wake up waiting for
                KeSetEvent(&g_Global_Data.m_WaitProcessEvent, IO_NO_INCREMENT, FALSE);
            }

        } while (FALSE);

        if(Eprocess)
            ObDereferenceObject(Eprocess);
    }

}