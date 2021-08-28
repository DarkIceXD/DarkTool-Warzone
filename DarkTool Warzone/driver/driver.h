#pragma once
#include <Windows.h>
#include <cstdint>
#include <string_view>

namespace driver
{
	void	initialize(const std::wstring_view& process);
	uint32_t pid();
	void	deinitialize();

	bool	connect();
	void	disconnect();

	uint32_t read_memory(const uintptr_t address, const uintptr_t buffer, const size_t size);
	uint32_t write_memory(const uintptr_t address, const uintptr_t buffer, const size_t size);
	uint64_t get_process_base_address();
	uint64_t clean_piddbcachetable();
	uint64_t clean_mmunloadeddrivers();
	uint64_t spoof_drives();
	uint64_t get_peb();

	template <typename T>
	T read(const uintptr_t address)
	{
		T buffer;
		read_memory(address, uint64_t(&buffer), sizeof(T));

		return buffer;
	}

	template <typename T>
	void write(const uintptr_t address, const T& buffer)
	{
		write_memory(address, uint64_t(&buffer), sizeof(T));
	}
}