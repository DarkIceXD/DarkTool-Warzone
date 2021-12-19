#pragma once
#include "../imgui/imgui.h"
#include "../game/data.h"
#include <windows.h>
#include <cstdint>

namespace target {
	inline HWND hwnd;
}

namespace overlay_window {
	inline HINSTANCE hInstance;
	inline HWND hwnd;
}

namespace overlay {
	bool create_overlay(const uint32_t pid);
	void render(data::game& data);
	void draw(data::game& data, ImDrawList* d);
	void menu();
	void destroy();
}