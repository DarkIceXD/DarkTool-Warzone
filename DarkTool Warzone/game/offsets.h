#pragma once

namespace offsets {
	constexpr auto refdef = 0x179EA4F0;
	constexpr auto name_array = 0x179F5B68;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x156E0760;
	constexpr auto camera_pos = 0x1D8;
	constexpr auto local_index = 0xE88;
	constexpr auto local_index_pos = 0x1FC;
	constexpr auto distribute = 0x1A08A978;
	constexpr auto visible = 0x63ECB70;

	namespace player {
		constexpr auto size = 0x3A98;
		constexpr auto valid = 0x2FC;
		constexpr auto pos = 0xA90;
		constexpr auto team = 0x20;
		constexpr auto stance = 0xDEC;
		constexpr auto dead_1 = 0x614;
		constexpr auto dead_2 = 0x978;
	}

	namespace bone {
		constexpr auto base_pos = 0x24294;
		constexpr auto index_struct_size = 0x150;
	}
}