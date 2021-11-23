#pragma once

namespace offsets {
	constexpr auto refdef = 0x18070A08;
	constexpr auto name_array = 0x1807C248;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x157F5CD0;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x34D20;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A722978;
	constexpr auto visible = 0x6198540;

	namespace player {
		constexpr auto size = 0x3AB8;
		constexpr auto valid = 0x544;
		constexpr auto pos = 0x4F8;
		constexpr auto team = 0x3F0;
		constexpr auto stance = 0x32FC;
		constexpr auto dead_1 = 0x66C;
		constexpr auto dead_2 = 0x5C8;
	}

	namespace bone {
		constexpr auto base_pos = 0x38E6C;
		constexpr auto index_struct_size = 0x150;
	}
}