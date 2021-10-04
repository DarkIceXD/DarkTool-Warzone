#include "driver.h"
#include "imports.h"

static uint64_t get_base(const packet::get_base& packet)
{
	PEPROCESS process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.process_id), &process)))
		return 0;

	const auto base_address = uint64_t(PsGetProcessSectionBaseAddress(process));
	ObDereferenceObject(process);
	return base_address;
}

static uint64_t get_peb(const packet::get_peb& packet)
{
	PEPROCESS process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.process_id), &process)))
		return 0;

	const auto peb_base_address = uint64_t(PsGetProcessPeb(process));
	ObDereferenceObject(process);
	return peb_base_address;
}

static uint64_t copy_memory(const packet::copy_memory& packet)
{
	PEPROCESS src_process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.src_process_id), &src_process)))
		return false;

	PEPROCESS dest_process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.dest_process_id), &dest_process)))
	{
		ObDereferenceObject(src_process);
		return false;
	}

	SIZE_T return_size = 0;
	if (!NT_SUCCESS(MmCopyVirtualMemory(src_process, (void*)packet.src_address, dest_process, (void*)packet.dest_address, packet.size, UserMode, &return_size)))
	{
		ObDereferenceObject(src_process);
		ObDereferenceObject(dest_process);
		return false;
	}

	ObDereferenceObject(src_process);
	ObDereferenceObject(dest_process);
	return true;
}

uint64_t driver::handle_packet(const packet& packet)
{
	switch (packet.type)
	{
	case packet::type::get_base:
		return get_base(packet.data.get_base);
	case packet::type::get_peb:
		return get_peb(packet.data.get_peb);
	case packet::type::copy_memory:
		return copy_memory(packet.data.copy_memory);
	default:
		return false;
	}
}