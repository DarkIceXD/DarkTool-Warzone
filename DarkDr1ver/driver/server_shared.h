#pragma once
#include "stdint.h"

struct packet {
	enum class type {
		completed,
		get_base,
		get_peb,
		copy_memory
	};

	struct completed {
		uint64_t result;
	};

	struct get_base {
		uint32_t process_id;
	};

	struct get_peb {
		uint32_t process_id;
	};

	struct copy_memory {
		uint32_t src_process_id;
		uint32_t dest_process_id;
		uint64_t src_address;
		uint64_t dest_address;
		uint32_t size;
	};

	type type;
	union
	{
		completed completed;
		get_base get_base;
		get_peb get_peb;
		copy_memory copy_memory;
	} data;
};