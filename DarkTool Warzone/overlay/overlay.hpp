#pragma once
#include "../imgui/imgui.h"
#include <windows.h>

namespace overlay
{
	inline HWND target_window;
	inline HWND overlay_window;
	bool create_overlay(LPCWSTR window_name);
	bool begin();
	void present();
	void draw(ImDrawList* d);
	void menu();
	void end();
};