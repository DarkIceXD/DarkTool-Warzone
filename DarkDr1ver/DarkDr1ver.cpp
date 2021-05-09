#include "log.h"
#include "server.h"

NTSTATUS DriverEntry()
{
	HANDLE thread_handle = nullptr;

	// Create server thread that will wait for incoming connections.
	const auto status = PsCreateSystemThread(
		&thread_handle,
		GENERIC_ALL,
		nullptr,
		nullptr,
		nullptr,
		server_thread,
		nullptr
	);

	if (!NT_SUCCESS(status))
	{
		log("Failed to create server thread. Status code: %X.", status);
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(thread_handle);
	return STATUS_SUCCESS;
}