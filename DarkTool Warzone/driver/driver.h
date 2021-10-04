#pragma once
#include <Windows.h>
#include <cstdint>
#include <string_view>

namespace driver {
	enum class status {
		success,
		events_failed,
		process_not_found,
		driver_connection_failed
	};
	status initialize(const std::string_view& process);
	void deinitialize();
	uint32_t pid();
	uint64_t get_base();
	uint64_t get_peb();
	uint32_t read_memory(const uintptr_t address, const uintptr_t buffer, const size_t size);
	uint32_t write_memory(const uintptr_t address, const uintptr_t buffer, const size_t size);
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