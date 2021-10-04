#pragma once
#include <cstdint>

namespace utils {
	constexpr bool is_valid_ptr(const uintptr_t ptr)
	{
		constexpr auto minimum = 0x1000;
		constexpr auto maximum = 0x7FFFFFFEFFFF;
		return ptr >= minimum && ptr <= maximum;
	}
}