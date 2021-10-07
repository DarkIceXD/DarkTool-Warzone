#pragma once

namespace offsets {
	constexpr auto refdef = 0x18047438;
	constexpr auto name_array = 0x18052C78;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x158116E0;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x2A670;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A6F5978;
	constexpr auto visible = 0x63837C0;

	namespace player {
		constexpr auto size = 0x3AE0;
		constexpr auto valid = 0x3D8;
		constexpr auto pos = 0x13F8;
		constexpr auto team = 0x1368;
		constexpr auto stance = 0xBC0;
		constexpr auto dead_1 = 0x13D8;
		constexpr auto dead_2 = 0xB28;
	}

	namespace bone {
		constexpr auto base_pos = 0x6219C;
		constexpr auto index_struct_size = 0x150;
	}
}