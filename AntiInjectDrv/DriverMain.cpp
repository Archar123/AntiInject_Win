#include "Anti-InjectBase.h"
#include "NtosApi.h"
#include "Anti-InjectCallback.h"
#include "Anti-InjectMiniFilter.h"

GLOBAL_DATA g_Global_Data = { 0x00 };
SYSTEM_DYNAMIC_DATA g_System_Dynamic_Data;

#ifdef __cplusplus
extern "C"
{ 
NTSTATUS FindSystemProcess(_In_ HANDLE ProcessId,
    _In_ UNICODE_STRING* ProcessName,
    _Out_ PEPROCESS* pSystemProcess
)
{
    NTSTATUS ntStatus = STATUS_NOT_FOUND;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PSYSTEM_PROCESS_INFORMATION pCurrentProcInfo = NULL;
    ULONG dwRet = 0;
    LIST_ENTRY* pEntry = NULL;
    ANTI_INJECT_PROTECT_PROCESS_DATA* pInjectData;

    do
    {
        ntStatus = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwRet);
        if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INFO_LENGTH_MISMATCH)
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_NOT_FOUND;
            break;
        }
        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, 2 * dwRet,'PsyS');
        if (!pProcInfo)
        {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = NtQuerySystemInformation(SystemProcessInformation, pProcInfo, 2 * dwRet,&dwRet);
        if (!NT_SUCCESS(ntStatus))
            break;
        if (dwRet == 0)
        {
            ntStatus = STATUS_NOT_FOUND;
            break;
        }

        pCurrentProcInfo = pProcInfo;
        while (1)
        {
            //reset ntStatus
            ntStatus = STATUS_NOT_FOUND;
            if (ProcessId != 0)
            {
                if (pCurrentProcInfo->UniqueProcessId == ProcessId)
                {
                    ntStatus = PsLookupProcessByProcessId(pCurrentProcInfo->UniqueProcessId,pSystemProcess);
                    if (!NT_SUCCESS(ntStatus))
                        break;

                    ntStatus = STATUS_SUCCESS;
                    break;
                }
            }
            else
            {
                if (pCurrentProcInfo->ImageName.Buffer != NULL &&
                    RtlCompareUnicodeString(&pCurrentProcInfo->ImageName, ProcessName, FALSE) == 0)
                {
                    ntStatus = PsLookupProcessByProcessId(pCurrentProcInfo->UniqueProcessId, pSystemProcess);
                    if (!NT_SUCCESS(ntStatus))
                        break;

                    LockList(&g_Global_Data.m_ProtectProcessListLock);

                    do 
                    {
                        if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;
                        if (!pEntry || !MmIsAddressValid(pEntry))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pInjectData = CONTAINING_RECORD(pEntry, ANTI_INJECT_PROTECT_PROCESS_DATA, m_Entry);
                        if (!pInjectData || !MmIsAddressValid(pInjectData))
                        {
                            ntStatus = STATUS_NOT_FOUND;
                            break;
                        }

                        pInjectData->m_Eprocess = *pSystemProcess;

                        ntStatus = STATUS_SUCCESS;

                    } while (FALSE);

                    
                    UnlockList(&g_Global_Data.m_ProtectProcessListLock);
                    
                    break;
                }
            }

            if (pCurrentProcInfo->NextEntryOffset == 0)
                break;

            pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrentProcInfo +pCurrentProcInfo->NextEntryOffset);

        }
    } while (FALSE);

    if (pProcInfo)
        ExFreePoolWithTag(pProcInfo, 0);

    return ntStatus;
}
 //Generic distribution function
 NTSTATUS DispatchCommon(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
 {
     UNREFERENCED_PARAMETER(pDeviceObject);

     NTSTATUS ntStatus = STATUS_SUCCESS;
     pIrp->IoStatus.Status = ntStatus;
     pIrp->IoStatus.Information = 0;

     IoCompleteRequest(pIrp, IO_NO_INCREMENT);

     return ntStatus;
 }

 NTSTATUS StartLoadImageRoutine()
 {
     return PsSetLoadImageNotifyRoutine(AntiInjectLoadImageRoutine);
 }

 VOID RemoveObCallback()
 {
     ObUnRegisterCallbacks((PVOID)g_Global_Data.m_ObRegistrationHandle);
     g_Global_Data.m_IsSetObCallback = FALSE;
 }

 NTSTATUS StopLoadImageRoutine()
 {
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     Status = PsRemoveLoadImageNotifyRoutine(AntiInjectLoadImageRoutine);
     if (NT_SUCCESS(Status))
     {
         g_Global_Data.m_IsSetPsSetLoadImage = FALSE;
     }
     return Status;
 }

 VOID StopObRegisterCallback(VOID)
 {
     ObUnRegisterCallbacks(g_Global_Data.m_ObRegistrationHandle);
     g_Global_Data.m_IsSetObCallback = FALSE;
 }

 NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDevicceObject, PIRP pIrp)
 {
     UNREFERENCED_PARAMETER(pDevicceObject);

     NTSTATUS ntStatus = STATUS_SUCCESS;
     IO_STACK_LOCATION* pCurrentIrpStack = IoGetCurrentIrpStackLocation(pIrp);
     ULONG dwControlCode = pCurrentIrpStack->Parameters.DeviceIoControl.IoControlCode;
     KAPC_STATE kApcState = { 0x00 };

     //Execute different logicand parse different SystemBuffers according to different control codes
     switch (dwControlCode)
     {
        case ACCTL_CODE_CONFIG:
        {
            StopObRegisterCallback();
        }
        break;
     }
     
     pIrp->IoStatus.Status = ntStatus;
     pIrp->IoStatus.Information = 0;
     IoCompleteRequest(pIrp, IO_NO_INCREMENT);
     return ntStatus;
 }

 VOID StopAntiInject(VOID)
 {
     if (g_Global_Data.m_isUnloaded)
     {
         //Only if everything is initialized successfully,Indicates that the protection thread is open and needs to wait for unloading

         //for g_Global_Data.m_IsInitMiniFilter, FltUnRegisterFilter,This is set to FALSE, so don't need to judge this field   
         if (g_Global_Data.m_IsSetObCallback &&
             g_Global_Data.m_IsSetPsSetLoadImage)
         {
             //Before uninstalling, close the detection thread, and after confirming that it is closed, perform subsequent work
             KeWaitForSingleObject(&g_Global_Data.m_WaitUnloadEvent, Executive, KernelMode, FALSE, NULL);
             //Until then, in ProtectThreadWork, the sleeping tasks are not complete, and wait for them to finish
             KrnlSleep(5000);
         }

         //If the system thread created by the driver is still waiting for the protection process while unloading, we need to set the event to wake up the wait
         KeSetEvent(&g_Global_Data.m_WaitProcessEvent, IO_NO_INCREMENT, FALSE);
     }

     //Wait a minute 
     KrnlSleep(1000);

     if (g_Global_Data.m_IsSetObCallback)
     {
         RemoveObCallback();
     }
     if (g_Global_Data.m_IsSetPsSetLoadImage)
     {
         StopLoadImageRoutine();
     }
     if (g_Global_Data.m_IsInitMiniFilter)
     {
         UnloadMiniFilter(0);
     }
 }

 VOID DriverUnload(PDRIVER_OBJECT pDrvObject)
 {
     UNICODE_STRING uSymboliclinkName = { 0x00 };     
     RtlInitUnicodeString(&uSymboliclinkName, L"\\device\\Anti-Inject");

     if (g_Global_Data.m_isUnloaded == FALSE)
         g_Global_Data.m_isUnloaded = TRUE;
     //close Protect...
     StopAntiInject();

     LockList(&g_Global_Data.m_BlackListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_BlackListHeader);
     UnlockList(&g_Global_Data.m_BlackListLock);

     LockList(&g_Global_Data.m_WhiteListLock);
     KrnlRemoveBlackWhiteList(&g_Global_Data.m_WhiteListHeader);
     UnlockList(&g_Global_Data.m_WhiteListLock);

     LockList(&g_Global_Data.m_ProtectProcessListLock);
     KrnlRemoveProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
     UnlockList(&g_Global_Data.m_ProtectProcessListLock);

     ExDeleteResourceLite(&g_Global_Data.m_WhiteListLock);
     ExDeleteResourceLite(&g_Global_Data.m_BlackListLock);
     ExDeleteResourceLite(&g_Global_Data.m_ProtectProcessListLock);
     
     IoDeleteSymbolicLink(&uSymboliclinkName);
     IoDeleteDevice(pDrvObject->DeviceObject);

     AkrOsPrint(("Unload Anti-Inject!\n"));
 }

 NTSTATUS StartAntiyInject()
 {
     NTSTATUS Status = STATUS_UNSUCCESSFUL;
     
     do 
     {
         Status = InitMiniFilter(g_Global_Data.m_DriverObject);
         if (!NT_SUCCESS(Status))
             break;
         g_Global_Data.m_IsInitMiniFilter = TRUE;

         Status = StartLoadImageRoutine();
         if (!NT_SUCCESS(Status))
             break;

         g_Global_Data.m_IsSetPsSetLoadImage = TRUE;

     } while (FALSE);

     return Status;
 }

VOID AntiInjectWork(PVOID pContext)
 {
     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     LIST_ENTRY* pEntry = NULL;
     ANTI_INJECT_PROTECT_PROCESS_DATA* ProtectData = NULL;
     PEPROCESS ProtectEprocess = NULL;
     UNICODE_STRING uProcessName = { 0x00 };
     PVOID pObjects[2] = {0x00};

     __try
     {
         LockList(&g_Global_Data.m_ProtectProcessListLock);
         if (IsListEmpty(&g_Global_Data.m_ProtectProcessListHeader))
         {
             UnlockList(&g_Global_Data.m_ProtectProcessListLock);
             __leave;
         }
         pEntry = g_Global_Data.m_ProtectProcessListHeader.Flink;

         UnlockList(&g_Global_Data.m_ProtectProcessListLock);

         ProtectData = CONTAINING_RECORD(pEntry, ANTI_INJECT_PROTECT_PROCESS_DATA, m_Entry);
         if (!ProtectData || !MmIsAddressValid(ProtectData))
             __leave;

         RtlInitUnicodeString(&uProcessName, ProtectData->m_Name);

         ntStatus = FindSystemProcess(0, &uProcessName, &ProtectEprocess);
         if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_NOT_FOUND)
             __leave;
         if (ntStatus == STATUS_NOT_FOUND)
         {
             PsSetCreateProcessNotifyRoutine(AntiInjectCreateProcessNotifyRoutine, FALSE);

             AkrOsPrint("Wait Protect %wZ..........!\n", &uProcessName);
              
             //Wait for the protection process to start
             KeWaitForSingleObject(&g_Global_Data.m_WaitProcessEvent, Executive, KernelMode, FALSE, NULL);
             PsSetCreateProcessNotifyRoutine(AntiInjectCreateProcessNotifyRoutine, TRUE);
         }

         //If the WaitProcessEvent is not awakened by the unload
         if (!g_Global_Data.m_isUnloaded)
         {
             //Wait Protect Process Init...
             KrnlSleep(5000);

             AkrOsPrint("Find Launch Protect Process:%wZ!\n", &uProcessName);

             //General switch
             ntStatus = StartAntiyInject();
             if (!NT_SUCCESS(ntStatus))
                 __leave;
         }
     }
     __finally
     {
         pObjects[0] = (PVOID)&g_Global_Data.m_WaitUnloadEvent;
         pObjects[1] = (PVOID)&g_Global_Data.m_ProtectProcessOverEvent;
         
         KeWaitForMultipleObjects(2, pObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

         if (g_Global_Data.m_isUnloaded)
         {
             KeSetEvent(&g_Global_Data.m_WaitUnloadEvent, IO_NO_INCREMENT, FALSE);
             PsTerminateSystemThread(ntStatus);
         }  
         else
         {
             AntiInjectWork(pContext);
         }
     }
 }

 NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObject, PUNICODE_STRING pRegPath)
 {
     UNREFERENCED_PARAMETER(pRegPath);

     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     ULONG i;
     UNICODE_STRING uDeviceName = { 0x00 };
     UNICODE_STRING uSymboliclinkName = { 0x00 };
     DEVICE_OBJECT* pDeviceObject = { 0x00 };
     HANDLE hThread = NULL;

     do
     {
         RtlInitUnicodeString(&uDeviceName, L"\\device\\Anti-Inject");
         ntStatus = IoCreateDevice(pDrvObject,
             0,
             &uDeviceName,
             FILE_DEVICE_UNKNOWN,
             0,
             FALSE,
             &pDeviceObject
         );

         if (!NT_SUCCESS(ntStatus))
         {
             AkrOsPrint("Create Device Object Fail:%d!\n", ntStatus);
             break;
         }

         RtlInitUnicodeString(&uSymboliclinkName, L"\\DosDevices\\Anti-Inject");
         ntStatus = IoCreateSymbolicLink(&uSymboliclinkName, &uDeviceName);

         if (!NT_SUCCESS(ntStatus))
         {
             AkrOsPrint("Create SymbolicLink Fail:%d!\n", ntStatus);
             break;
         }

         for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
         {
             pDrvObject->MajorFunction[i] = DispatchCommon;
         }

         pDrvObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
         pDrvObject->DriverUnload = DriverUnload;

         InitializeListHead(&g_Global_Data.m_WhiteListHeader);
         ExInitializeResourceLite (&g_Global_Data.m_WhiteListLock);

         InitializeListHead(&g_Global_Data.m_BlackListHeader);
         ExInitializeResourceLite(&g_Global_Data.m_BlackListLock);

         InitializeListHead(&g_Global_Data.m_ProtectProcessListHeader);
         ExInitializeResourceLite (&g_Global_Data.m_ProtectProcessListLock);

         //init System Data...
         RtlZeroMemory(&g_System_Dynamic_Data, sizeof(SYSTEM_DYNAMIC_DATA));
         InitDynamicData(&g_System_Dynamic_Data);

         //setup Whitelist...
         LockList(&g_Global_Data.m_WhiteListLock);
         UpdateWhiteList(&g_Global_Data.m_WhiteListHeader);
         LookupList(&g_Global_Data.m_WhiteListHeader);
         UnlockList(&g_Global_Data.m_WhiteListLock);

         //setup BlackList
         LockList(&g_Global_Data.m_BlackListLock);
         UpdateBlackList(&g_Global_Data.m_BlackListHeader);
         LookupList(&g_Global_Data.m_BlackListHeader);
         UnlockList(&g_Global_Data.m_BlackListLock);

         //setup Protect Process
         LockList(&g_Global_Data.m_ProtectProcessListLock);
         UpdateProtectProcessList(&g_Global_Data.m_ProtectProcessListHeader);
         LookupList(&g_Global_Data.m_ProtectProcessListHeader);
         UnlockList(&g_Global_Data.m_ProtectProcessListLock);

         g_Global_Data.m_DriverObject = pDrvObject;
         g_Global_Data.m_isUnloaded = FALSE;

         KeInitializeEvent(&g_Global_Data.m_WaitUnloadEvent, SynchronizationEvent, FALSE);
         KeInitializeEvent(&g_Global_Data.m_WaitProcessEvent, SynchronizationEvent, FALSE);
         KeInitializeEvent(&g_Global_Data.m_ProtectProcessOverEvent, SynchronizationEvent, FALSE);
         ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, AntiInjectWork, NULL);
         if (!NT_SUCCESS(ntStatus))
         {
             AkrOsPrint("Create System Thread Fail:0x%x!\n", ntStatus);
             break;
         }

         ZwClose(hThread);
     } while (FALSE);

     if (NT_SUCCESS(ntStatus))
     {
         AkrOsPrint("Anti-Inject Driver Start Success!\n");
     }
     else
     {
         if (pDeviceObject)
         {
             AkrOsPrint("Anti-Inject Driver Start Fail!\n");
             g_Global_Data.m_isUnloaded = TRUE;
             DriverUnload(pDrvObject);
         }
     }
     return ntStatus;
 }

 NTSTATUS InitDynamicData(_Out_ PSYSTEM_DYNAMIC_DATA pData)
 {
     NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
     OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
     ULONG ShortVersion = 0;

     do 
     {
         ntStatus = RtlGetVersion((PRTL_OSVERSIONINFOW)&VersionInfo);
         if (!NT_SUCCESS(ntStatus))
         {
             break;
         }

         ShortVersion = (VersionInfo.dwMajorVersion << 8) | (VersionInfo.dwMinorVersion << 4) | (VersionInfo.wServicePackMajor);
         
         pData->Version = (_WinVer)ShortVersion;

         if (ShortVersion < WINVER_7)
         {
             ntStatus = STATUS_NOT_SUPPORTED;
             break;
         }

         switch (ShortVersion)
         {
             case WINVER_7:
             case WINVER_7_SP1:
             {
                 pData->EProcessFlagsOffset = 0x440;
             }
             break;
             case WINVER_81:
             {
                 pData->EProcessFlagsOffset = 0x2fc;
             }
             break;
             case WINVER_10:
             {
                 if (VersionInfo.dwBuildNumber == 16299 ||
                     VersionInfo.dwBuildNumber == 17134 || 
                     VersionInfo.dwBuildNumber == 17763)
                 {
                     pData->EProcessFlagsOffset = 0x304;
                 }
                 else if (VersionInfo.dwBuildNumber >= 18362)
                 {
                     pData->EProcessFlagsOffset = 0x30c;
                 }
             }
             break;
         }


     } while (FALSE);
     

     return ntStatus;
 }

#endif

#ifdef __cplusplus
}
#endif