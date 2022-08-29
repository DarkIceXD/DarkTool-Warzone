#pragma once

namespace offsets {
	constexpr auto refdef = 0x156DB850;
	constexpr auto name_array = 0x156E7FB0;
	constexpr auto name_array_pos = 0x4C70;
	constexpr auto camera_base = 0x12BE7EA0;
	constexpr auto camera_pos = 0x1E8;
	constexpr auto local_index = 0x8EFE8;
	constexpr auto local_index_pos = 0x204;
	constexpr auto distribute = 0x17E10D28;
	constexpr auto visible = 0x63F79D0;

	namespace player {
		constexpr auto size = 0x6108;
		constexpr auto valid = 0x340;
		constexpr auto pos = 0x200;
		constexpr auto team = 0x5290;
		constexpr auto stance = 0x545C;
		constexpr auto dead_1 = 0xA0;
		constexpr auto dead_2 = 0x374;
	}

	namespace bone {
		constexpr auto base_pos = 0x7310C;
		constexpr auto index_struct_size = 0x150;
	}
}