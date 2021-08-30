#include "overlay.hpp"
#include "../imgui/imgui_impl_dx9.h"
#include "../imgui/imgui_impl_win32.h"
#include <d3d9.h>
#pragma comment( lib, "d3d9.lib" )
#include <dwmapi.h>
#include "../game/globals.h"
#pragma comment( lib, "dwmapi.lib" )

struct window_rect_data_t : public RECT
{
	constexpr int width() const { return right - left; }
	constexpr int height() const { return bottom - top; }
};

static HWND target_window;
static window_rect_data_t target_window_size;
static IDirect3DDevice9* direct_device;

LRESULT CALLBACK mouse_manager(int nCode, WPARAM wParam, LPARAM lParam) {
	MOUSEHOOKSTRUCT* pMouseStruct = (MOUSEHOOKSTRUCT*)lParam;
	if (pMouseStruct != NULL) {
		ImGuiIO& io = ImGui::GetIO();
		switch (wParam)
		{
		case WM_LBUTTONDOWN:
			io.MouseDown[0] = true;
			break;
		case WM_LBUTTONUP:
			io.MouseDown[0] = false;
			io.MouseReleased[0] = true;
			break;
		case WM_RBUTTONDOWN:
			io.MouseDown[1] = true;
			break;
		case WM_RBUTTONUP:
			io.MouseDown[1] = false;
			io.MouseReleased[1] = true;
			break;
		}
	}
	return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
	ImGuiIO& io = ImGui::GetIO();
	switch (message)
	{
	case WM_MOUSEMOVE:
		io.MousePos.x = (signed short)(lparam);
		io.MousePos.y = (signed short)(lparam >> 16);
		break;
	}

	if (ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam))
		return true;

	if (message == WM_DESTROY)
		ExitProcess(EXIT_SUCCESS);

	return DefWindowProcW(window, message, wparam, lparam);
}

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
	DWORD lpdwProcessId;
	GetWindowThreadProcessId(hwnd, &lpdwProcessId);
	if (lpdwProcessId == lParam)
	{
		target_window = hwnd;
		return FALSE;
	}
	return TRUE;
}

bool overlay::create_overlay(const uint32_t pid) {
	constexpr auto tite = L"Hammer & Chisel Inc.";
	WNDCLASSEX window_class_ex;
	window_class_ex.cbSize = sizeof(WNDCLASSEX);
	window_class_ex.style = CS_HREDRAW | CS_VREDRAW;
	window_class_ex.lpfnWndProc = WndProc;
	window_class_ex.cbClsExtra = 0;
	window_class_ex.cbWndExtra = 0;
	window_class_ex.hInstance = nullptr;
	window_class_ex.hIcon = nullptr;
	window_class_ex.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	window_class_ex.hbrBackground = HBRUSH(RGB(0, 0, 0));
	window_class_ex.lpszMenuName = L"";
	window_class_ex.lpszClassName = tite;
	window_class_ex.hIconSm = nullptr;

	ImGui::CreateContext();

	if (!RegisterClassExW(&window_class_ex))
		return false;

	do {
		EnumWindows(EnumWindowsProcMy, pid);
		Sleep(1000);
	} while (!target_window);

	if (!GetWindowRect(target_window, &target_window_size))
		return false;

	overlay_window = CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_NOACTIVATE, tite, L"", WS_POPUP | WS_VISIBLE,
		target_window_size.left, target_window_size.top, target_window_size.width(), target_window_size.height(), nullptr, nullptr, nullptr, nullptr);

	if (!overlay_window)
		return false;

	MARGINS margins = { target_window_size.left, target_window_size.top, target_window_size.width(), target_window_size.height() };
	DwmExtendFrameIntoClientArea(overlay_window, &margins);

	if (!SetLayeredWindowAttributes(overlay_window, RGB(0, 0, 0), 255, LWA_ALPHA))
		return false;

	if (!SetWindowDisplayAffinity(overlay_window, WDA_EXCLUDEFROMCAPTURE))
		return false;

	if (!ShowWindow(overlay_window, SW_SHOW))
		return false;

	const auto direct = Direct3DCreate9(D3D_SDK_VERSION);
	if (!direct)
		return false;

	D3DPRESENT_PARAMETERS parameters = { };
	parameters.Windowed = true;
	parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
	parameters.BackBufferFormat = D3DFMT_A8R8G8B8;
	parameters.BackBufferWidth = target_window_size.width();
	parameters.BackBufferHeight = target_window_size.height();
	parameters.hDeviceWindow = overlay_window;
	parameters.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

	const auto result = direct->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, overlay_window, D3DCREATE_HARDWARE_VERTEXPROCESSING, &parameters, &direct_device);
	if (FAILED(result))
		return false;

	if (!ImGui_ImplWin32_Init(overlay_window))
		return false;

	if (!ImGui_ImplDX9_Init(direct_device))
		return false;

	{ // Load ImGui theme
		auto& style = ImGui::GetStyle();
		style.Colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.63f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.67f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.67f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.18f, 0.18f, 0.18f, 0.39f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.61f, 0.00f, 1.00f, 0.24f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.61f, 0.00f, 1.00f, 0.39f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.61f, 0.00f, 1.00f, 0.39f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.61f, 0.00f, 1.00f, 0.24f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.61f, 0.00f, 1.00f, 0.73f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.61f, 0.00f, 1.00f, 0.47f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.61f, 0.00f, 1.00f, 0.75f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.61f, 0.00f, 1.00f, 0.78f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.61f, 0.00f, 1.00f, 0.47f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.61f, 0.00f, 1.00f, 0.47f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.61f, 0.00f, 1.00f, 0.24f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.61f, 0.00f, 1.00f, 0.39f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.61f, 0.00f, 1.00f, 0.39f);
		style.Colors[ImGuiCol_Tab] = ImVec4(0.61f, 0.00f, 1.00f, 0.24f);
		style.Colors[ImGuiCol_TabHovered] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TabActive] = ImVec4(0.61f, 0.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TableHeaderBg] = ImVec4(0.61f, 0.00f, 1.00f, 0.24f);
		style.GrabRounding = style.FrameRounding = 6;
		style.ItemSpacing = ImVec2(8, 6);
	}

	SetWindowsHookEx(WH_MOUSE, mouse_manager, 0, GetCurrentThreadId());

	return true;
}

bool overlay::begin() {
	direct_device->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.f, 0);
	direct_device->BeginScene();

	/*if (target_window != GetForegroundWindow())
	{
		direct_device->EndScene();
		direct_device->Present(nullptr, nullptr, nullptr, nullptr);

		return false;
	}*/

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	return true;
}

void overlay::present()
{
	static bool show_menu = false;
	if (GetAsyncKeyState(VK_INSERT) & 1) {
		show_menu = !show_menu;
		const auto style = GetWindowLong(overlay_window, GWL_EXSTYLE);
		const auto new_style = show_menu ? (style & ~WS_EX_LAYERED) : (style | WS_EX_LAYERED);
		SetWindowLong(overlay_window, GWL_EXSTYLE, new_style);
	}

	if (show_menu)
		menu();

	draw(ImGui::GetForegroundDrawList());
}

void overlay::end() {
	ImGui::EndFrame();
	ImGui::Render();
	ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());

	direct_device->EndScene();
	direct_device->Present(nullptr, nullptr, nullptr, nullptr);

	GetWindowRect(target_window, &target_window_size);
	SetWindowPos(overlay_window, HWND_TOP, target_window_size.left, target_window_size.top, target_window_size.width(), target_window_size.height(), SWP_ASYNCWINDOWPOS);
}