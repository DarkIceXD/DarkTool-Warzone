#pragma once

namespace offsets {
	constexpr auto refdef = 0x17932CB0;
	constexpr auto name_array = 0x1793E2D8;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x149B0E70;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x31DC0;
	constexpr auto local_index_pos = 0x1FC;
	namespace player {
		constexpr auto size = 0x3AE0;
		constexpr auto valid = 0x504;
		constexpr auto pos = 0x100;
		constexpr auto team = 0x4D0;
		constexpr auto stance = 0x98C;
		constexpr auto dead_1 = 0x27C;
		constexpr auto dead_2 = 0x570;
	}
	namespace bone {
		constexpr auto base_pos = 0x2DC;
		constexpr auto index_struct_size = 0x150;
	}
}