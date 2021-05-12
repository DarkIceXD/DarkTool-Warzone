#pragma once
#include <WinSock2.h>
#include <cstdint>

namespace driver
{
	void	initialize();
	void	deinitialize();

	bool	connect();
	void	disconnect();

	uint32_t read_memory(const uint32_t process_id, const uintptr_t address, const uintptr_t buffer, const size_t size);
	uint32_t write_memory(const uint32_t process_id, const uintptr_t address, const uintptr_t buffer, const size_t size);
	uint64_t get_process_base_address(const uint32_t process_id);
	uint64_t clean_piddbcachetable();
	uint64_t clean_mmunloadeddrivers();
	uint64_t spoof_drives();
	uint64_t get_peb(const uint32_t process_id);

	template <typename T>
	T read(const uint32_t process_id, const uintptr_t address)
	{
		T buffer;
		read_memory(process_id, address, uint64_t(&buffer), sizeof(T));

		return buffer;
	}

	template <typename T>
	void write(const uint32_t process_id, const uintptr_t address, const T& buffer)
	{
		write_memory(process_id, address, uint64_t(&buffer), sizeof(T));
	}
}