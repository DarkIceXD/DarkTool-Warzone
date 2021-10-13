#pragma once

namespace offsets {
	constexpr auto refdef = 0x17E24638;
	constexpr auto name_array = 0x17E2FE78;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x155EE8E0;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0x37530;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A4D2978;
	constexpr auto visible = 0x6135690;

	namespace player {
		constexpr auto size = 0x3AC8;
		constexpr auto valid = 0x1220;
		constexpr auto pos = 0x148;
		constexpr auto team = 0xD0;
		constexpr auto stance = 0x278;
		constexpr auto dead_1 = 0x3A10;
		constexpr auto dead_2 = 0xD7C;
	}

	namespace bone {
		constexpr auto base_pos = 0x3A4;
		constexpr auto index_struct_size = 0x150;
	}
}