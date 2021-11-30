#include <ntifs.h>
#include "driver/driver.h"

HANDLE start = NULL;
HANDLE finished = NULL;
HANDLE thread_handle = NULL;
WCHAR SharedSectionName[] = L"\\BaseNamedObjects\\DarkShare";
HANDLE section_handle;
PVOID section = NULL;
PACL dacl;

NTSTATUS create_shared_memory()
{
	NTSTATUS status = STATUS_SUCCESS;

	SECURITY_DESCRIPTOR sec_descriptor;
	status = RtlCreateSecurityDescriptor(&sec_descriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "RtlCreateSecurityDescriptor failed: %d\n", status);
		return status;
	}

	ULONG dacl_length = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);

	dacl = (PACL)ExAllocatePoolWithTag(PagedPool, dacl_length, 'lcaD');
	if (dacl == NULL) {
		DbgPrintEx(0, 0, "ExAllocatePoolWithTag failed: %d\n", status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = RtlCreateAcl(dacl, dacl_length, ACL_REVISION);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "RtlCreateAcl failed: %d\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeWorldSid failed: %d\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeAliasAdminsSid);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeAliasAdminsSid failed: %d\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeLocalSystemSid);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid failed: %d\n", status);
		return status;
	}

	status = RtlSetDaclSecurityDescriptor(&sec_descriptor, TRUE, dacl, FALSE);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor failed: %d\n", status);
		return status;
	}

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, SharedSectionName);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &sec_descriptor);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	status = ZwCreateSection(&section_handle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL); // Create section with section handle, object attributes, and the size of shared mem struct
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		DbgPrintEx(0, 0, "ZwCreateSection failed: %d\n", status);
		return status;
	}

	SIZE_T ulViewSize = 1024 * 10;   // &sectionHandle before was here i guess i am correct 
	status = ZwMapViewOfSection(section_handle, NtCurrentProcess(), &section, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(status)) {
		ExFreePool(dacl);
		ZwClose(section_handle);
		DbgPrintEx(0, 0, "ZwMapViewOfSection failed: %d\n", status);
		return status;
	}

	ExFreePool(dacl);
	return STATUS_SUCCESS;
}

NTSTATUS create_events() {
	NTSTATUS status;

	UNICODE_STRING event_start;
	RtlInitUnicodeString(&event_start, L"\\BaseNamedObjects\\DarkStart");
	OBJECT_ATTRIBUTES obj_attr;
	InitializeObjectAttributes(&obj_attr, &event_start, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0);
	status = ZwOpenEvent(&start, EVENT_ALL_ACCESS, &obj_attr);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "ZwOpenEvent failed (DarkStart): %d\n", status);
		return status;
	}

	UNICODE_STRING event_finished;
	RtlInitUnicodeString(&event_finished, L"\\BaseNamedObjects\\DarkFinished");
	OBJECT_ATTRIBUTES obj_attr2;
	InitializeObjectAttributes(&obj_attr2, &event_finished, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0);
	status = ZwOpenEvent(&finished, EVENT_ALL_ACCESS, &obj_attr2);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "ZwOpenEvent failed (DarkFinished): %d\n", status);
		return status;
	}

	return STATUS_SUCCESS;
}

VOID loop(PVOID StartContext)
{
	NTSTATUS status;

	status = create_shared_memory();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "create_shared_memory failed: %d\n", status);
		return;
	}

	status = create_events();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "create_events failed: %d\n", status);
		return;
	}

	ZwSetEvent(finished, NULL);
	packet* data = (packet*)section;
	while (true)
	{
		ZwWaitForSingleObject(start, TRUE, NULL);
		data->data.completed.result = driver::handle_packet(*data);
		data->type = packet::type::completed;
		ZwSetEvent(finished, NULL);
	}
}

NTSTATUS DriverEntry() {
	NTSTATUS status;

	status = PsCreateSystemThread(
		&thread_handle,
		GENERIC_ALL,
		NULL,
		NULL,
		NULL,
		loop,
		NULL
	);

	return status;
}