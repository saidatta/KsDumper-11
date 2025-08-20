#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "UserModeBridge.h"
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

UNICODE_STRING deviceName, symLink;
PDEVICE_OBJECT deviceObject;

// Forward declare to avoid implicit declaration when used before definition
NTSTATUS GetProcessModules(INT32 targetProcessId, PKERNEL_MODULE_INFO modules, INT32 maxModules, INT32* moduleCount);

NTSTATUS CopyVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	PSIZE_T readBytes;
	return MmCopyVirtualMemory(targetProcess, sourceAddress, PsGetCurrentProcess(), targetAddress, size, UserMode, &readBytes);
}

// FIXED: Proper system module caching
static KERNEL_MODULE_INFO g_systemModules[100];
static ULONG g_systemModuleCount = 0;
static BOOLEAN g_systemModulesCached = FALSE;
static KSPIN_LOCK g_systemModulesLock;

NTSTATUS InitializeSystemModuleCache()
{
	// FIXED: Actually initialize the spinlock
	KeInitializeSpinLock(&g_systemModulesLock);
	g_systemModulesCached = FALSE;
	g_systemModuleCount = 0;
	return STATUS_SUCCESS;
}

NTSTATUS FindUserModeProcessForCaching(HANDLE* processId)
{
	// Find a proper user-mode process for caching system modules
	// Don't use PID 4 (System) - it has no user-mode modules

	// Use current process ID via kernel API
	HANDLE candidateProcesses[] = {
		PsGetCurrentProcessId(),
		// Could add logic to find csrss.exe, winlogon.exe, etc.
	};

	for (int i = 0; i < (int)(sizeof(candidateProcesses) / sizeof(HANDLE)); i++)
	{
		PEPROCESS process;
		NTSTATUS status = PsLookupProcessByProcessId(candidateProcesses[i], &process);

		if (NT_SUCCESS(status))
		{
			// Check if process has user-mode PEB
			PPEB peb = PsGetProcessPeb(process);
			if (peb != NULL)
			{
				*processId = candidateProcesses[i];
				ObDereferenceObject(process);
				return STATUS_SUCCESS;
			}
			ObDereferenceObject(process);
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS CacheSystemModules()
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_systemModulesLock, &oldIrql);

	if (!g_systemModulesCached)
	{
		HANDLE userModeProcessId;
		NTSTATUS status = FindUserModeProcessForCaching(&userModeProcessId);

		if (NT_SUCCESS(status))
		{
			// FIXED: Cache from a proper user-mode process
			status = GetProcessModules(HandleToUlong(userModeProcessId), g_systemModules, 100, &g_systemModuleCount);
			if (NT_SUCCESS(status))
			{
				g_systemModulesCached = TRUE;
			}
		}
	}

	KeReleaseSpinLock(&g_systemModulesLock, oldIrql);
	return g_systemModulesCached ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS GetProcessPEB(INT32 targetProcessId, PVOID* pebAddress)
{
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)targetProcessId, &targetProcess);

	if (NT_SUCCESS(status))
	{
		*pebAddress = PsGetProcessPeb(targetProcess);
		ObDereferenceObject(targetProcess);

		if (*pebAddress == NULL)
		{
			return STATUS_NOT_FOUND;
		}

		return STATUS_SUCCESS;
	}

	return status;
}

NTSTATUS GetProcessModules(INT32 targetProcessId, PKERNEL_MODULE_INFO modules, INT32 maxModules, INT32* moduleCount)
{
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)targetProcessId, &targetProcess);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// CRITICAL: Check IRQL level
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	PPEB peb = PsGetProcessPeb(targetProcess);
	if (peb == NULL)
	{
		ObDereferenceObject(targetProcess);
		return STATUS_NOT_FOUND;
	}

	*moduleCount = 0;

	// CRITICAL: Attach to target process for safe memory access
	KAPC_STATE apcState;
	KeStackAttachProcess(targetProcess, &apcState);

	__try
	{
		// CRITICAL: Probe user-mode memory before access (use PEB64 minimal size we rely on)
		ProbeForRead(peb, sizeof(PEB64), sizeof(ULONG_PTR));

		// Access PEB_LDR_DATA with proper validation via PEB64 view
		PPEB64 peb64 = (PPEB64)peb;
		PPEB_LDR_DATA ldr = peb64->Ldr;
		if (ldr == NULL)
		{
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// CRITICAL: Probe LDR_DATA before access
		ProbeForRead(ldr, sizeof(PEB_LDR_DATA), sizeof(ULONG_PTR));

		// Walk InLoadOrderModuleList with proper validation
		PLIST_ENTRY moduleList = &ldr->InLoadOrderModuleList;
		if (moduleList == NULL)
		{
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// CRITICAL: Probe module list before access
		ProbeForRead(moduleList, sizeof(LIST_ENTRY), sizeof(ULONG_PTR));

		PLIST_ENTRY currentEntry = moduleList->Flink;
		ULONG iterationCount = 0;

		while (currentEntry != NULL && currentEntry != moduleList && *moduleCount < maxModules)
		{
			// FIXED: Safety check to prevent infinite loops
			if (++iterationCount > 1000)
			{
				break;
			}

			// FIXED: Simplified approach - just try to access and catch exceptions
			// No MmIsAddressValid or ProbeForRead - they create race conditions
			PLDR_DATA_TABLE_ENTRY moduleEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			// Access module entry directly - exception handler will catch problems
			if (moduleEntry->DllBase != NULL && moduleEntry->SizeOfImage > 0 && moduleEntry->SizeOfImage < 0x10000000) // 256MB limit
			{
				modules[*moduleCount].baseAddress = moduleEntry->DllBase;
				modules[*moduleCount].sizeOfImage = moduleEntry->SizeOfImage;

				// FIXED: Detect process architecture properly
				modules[*moduleCount].isWow64Process = (PsGetProcessWow64Process(targetProcess) != NULL);

				// FIXED: Simplified name copying - just try and catch exceptions
				if (moduleEntry->BaseDllName.Buffer != NULL &&
					moduleEntry->BaseDllName.Length > 0 &&
					moduleEntry->BaseDllName.Length < 512)
				{
					__try
					{
						ULONG copyLength = min(moduleEntry->BaseDllName.Length, sizeof(modules[*moduleCount].moduleName) - sizeof(WCHAR));
						RtlCopyMemory(modules[*moduleCount].moduleName, moduleEntry->BaseDllName.Buffer, copyLength);
						modules[*moduleCount].moduleName[copyLength / sizeof(WCHAR)] = L'\0';
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						// If name copy fails, use default name
						wcscpy(modules[*moduleCount].moduleName, L"unknown.dll");
					}
				}
				else
				{
					wcscpy(modules[*moduleCount].moduleName, L"unknown.dll");
				}

				(*moduleCount)++;
			}

			// Move to next entry - exception handler will catch invalid pointers
			currentEntry = currentEntry->Flink;
		}

		status = STATUS_SUCCESS;
	}
	__except(GetExceptionCode() == STATUS_ACCESS_VIOLATION ||
			 GetExceptionCode() == STATUS_INVALID_ADDRESS ||
			 GetExceptionCode() == STATUS_PARTIAL_COPY ||
			 GetExceptionCode() == STATUS_INVALID_USER_BUFFER ||
			 GetExceptionCode() == STATUS_DATATYPE_MISALIGNMENT ?
			 EXCEPTION_EXECUTE_HANDLER :
			 EXCEPTION_CONTINUE_SEARCH)
	{
		// FIXED: Handle multiple relevant exception types
		status = GetExceptionCode();
	}

	// CRITICAL: Always detach from process
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);
	return status;
}

NTSTATUS UnsupportedDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

//NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
//{
//	IoDeleteSymbolicLink(&symLink);
//	IoDeleteDevice(DriverObject->DeviceObject);
//}

NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink(&symLink);
	IoDeleteSymbolicLink(&deviceName);
	IoDeleteDevice(deviceObject);
	return ZwUnloadDriver(&deviceName);
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	ULONG bytesIO = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IO_COPY_MEMORY)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_COPY_MEMORY_OPERATION))
		{
			PKERNEL_COPY_MEMORY_OPERATION request = (PKERNEL_COPY_MEMORY_OPERATION)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS targetProcess;

			if (NT_SUCCESS(PsLookupProcessByProcessId(request->targetProcessId, &targetProcess)))
			{
				CopyVirtualMemory(targetProcess, request->targetAddress, request->bufferAddress, request->bufferSize);
				ObDereferenceObject(targetProcess);
			}

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_COPY_MEMORY_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_PROCESS_LIST)
	{
		if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(KERNEL_PROCESS_LIST_OPERATION))
		{
			PKERNEL_PROCESS_LIST_OPERATION request = (PKERNEL_PROCESS_LIST_OPERATION)Irp->AssociatedIrp.SystemBuffer;

			GetProcessList(request->bufferAddress, request->bufferSize, &request->bufferSize, &request->processCount);

			status = STATUS_SUCCESS;
			bytesIO = sizeof(KERNEL_PROCESS_LIST_OPERATION);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_UNLOAD_DRIVER)
	{
		Unload(NULL);
		bytesIO = 0;
		status = STATUS_SUCCESS;
	}
	else if (controlCode == IO_GET_PROCESS_PEB)
	{
		// For METHOD_BUFFERED: both input and output are Irp->AssociatedIrp.SystemBuffer
		ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;

		if (inputBufferLength >= sizeof(KERNEL_GET_PEB_OPERATION) && outputBufferLength >= sizeof(KERNEL_GET_PEB_OPERATION))
		{
			PKERNEL_GET_PEB_OPERATION operation = (PKERNEL_GET_PEB_OPERATION)inputBuffer;
			operation->status = GetProcessPEB(operation->targetProcessId, &operation->pebAddress);
			bytesIO = sizeof(KERNEL_GET_PEB_OPERATION);
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
			bytesIO = 0;
		}
	}
	else if (controlCode == IO_GET_PROCESS_MODULES)
	{
		// For METHOD_BUFFERED: both input and output are Irp->AssociatedIrp.SystemBuffer
		ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;

		// Separate input/output structures in the same buffer
		if (inputBufferLength >= sizeof(KERNEL_GET_MODULES_INPUT) &&
			outputBufferLength >= FIELD_OFFSET(KERNEL_GET_MODULES_OUTPUT, modules))
		{
			PKERNEL_GET_MODULES_INPUT input = (PKERNEL_GET_MODULES_INPUT)inputBuffer;
			PKERNEL_GET_MODULES_OUTPUT output = (PKERNEL_GET_MODULES_OUTPUT)outputBuffer;

			// Calculate max modules that fit in output buffer
			INT32 maxModules = min(input->maxModules,
				(INT32)((outputBufferLength - FIELD_OFFSET(KERNEL_GET_MODULES_OUTPUT, modules)) / sizeof(KERNEL_MODULE_INFO)));

			if (maxModules > 1000) maxModules = 1000; // Safety limit

			// Get modules directly into output buffer
			output->status = GetProcessModules(input->targetProcessId, output->modules, maxModules, &output->moduleCount);

			// Calculate total bytes returned
			bytesIO = FIELD_OFFSET(KERNEL_GET_MODULES_OUTPUT, modules) + (output->moduleCount * sizeof(KERNEL_MODULE_INFO));
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
			bytesIO = 0;
		}
	}
	else
	{
		status = STATUS_INVALID_PARAMETER;
		bytesIO = 0;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;


	UNREFERENCED_PARAMETER(RegistryPath);

	// FIXED: Initialize system module cache
	status = InitializeSystemModuleCache();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	RtlInitUnicodeString(&deviceName, L"\\Device\\KsDumper");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\KsDumper");

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = IoCreateSymbolicLink(&symLink, &deviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		return status;
	}
	deviceObject->Flags |= DO_BUFFERED_IO;

	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl;
	DriverObject->DriverUnload = &Unload;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}



NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	return IoCreateDriver(NULL, &DriverInitialize);
}
