#include "overlay.hpp"
#include "../imgui/imgui_impl_dx9.h"
#include "../imgui/imgui_impl_win32.h"
#include "../imgui/implot.h"
#include <d3d9.h>
#pragma comment( lib, "d3d9.lib" )
#include <dwmapi.h>
#pragma comment( lib, "dwmapi.lib" )

constexpr auto title = L"Hammer & Chisel Inc.";

struct window_rect : public RECT
{
	constexpr int width() const { return right - left; }
	constexpr int height() const { return bottom - top; }
};

namespace directx9 {
	inline IDirect3D9Ex* IDirect3D9 = NULL;
	inline IDirect3DDevice9Ex* device = NULL;
	inline D3DPRESENT_PARAMETERS params = { NULL };
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WinProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, Message, wParam, lParam))
		return true;

	switch (Message) {
	case WM_DESTROY:
		if (directx9::device != NULL) {
			directx9::device->EndScene();
			directx9::device->Release();
		}
		if (directx9::IDirect3D9 != NULL) {
			directx9::IDirect3D9->Release();
		}
		PostQuitMessage(0);
		exit(4);
		break;
	case WM_SIZE:
		if (directx9::device != NULL && wParam != SIZE_MINIMIZED) {
			ImGui_ImplDX9_InvalidateDeviceObjects();
			directx9::params.BackBufferWidth = LOWORD(lParam);
			directx9::params.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = directx9::device->Reset(&directx9::params);
			if (hr == D3DERR_INVALIDCALL)
				IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		break;
	default:
		return DefWindowProc(hWnd, Message, wParam, lParam);
		break;
	}
	return 0;
}

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

BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
	DWORD lpdwProcessId;
	GetWindowThreadProcessId(hwnd, &lpdwProcessId);
	if (lpdwProcessId == lParam)
	{
		target::hwnd = hwnd;
		return FALSE;
	}
	return TRUE;
}

bool overlay::create_overlay(const uint32_t pid)
{
	WNDCLASSEX window_class = {
		sizeof(WNDCLASSEX), 0, WinProc, 0, 0, nullptr, LoadIcon(nullptr, IDI_APPLICATION), LoadCursor(nullptr, IDC_ARROW), nullptr, nullptr, title, LoadIcon(nullptr, IDI_APPLICATION)
	};
	RegisterClassEx(&window_class);
	overlay_window::hInstance = window_class.hInstance;
	do {
		EnumWindows(EnumWindowsProcMy, pid);
		Sleep(1000);
	} while (!target::hwnd);

	window_rect rect;
	if (!GetWindowRect(target::hwnd, &rect))
	{
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}
	overlay_window::hwnd = CreateWindowEx(NULL, title, title, WS_POPUP | WS_VISIBLE, rect.left, rect.top, rect.width(), rect.height(), nullptr, nullptr, nullptr, nullptr);
	SetWindowLong(overlay_window::hwnd, GWL_EXSTYLE, WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
	MARGINS margin = { -1 };
	if (!SUCCEEDED(DwmExtendFrameIntoClientArea(overlay_window::hwnd, &margin)))
	{
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}

	if (!SetWindowDisplayAffinity(overlay_window::hwnd, WDA_EXCLUDEFROMCAPTURE))
	{
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}

	if (!ShowWindow(overlay_window::hwnd, SW_SHOW))
	{
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}

	if (FAILED(Direct3DCreate9Ex(D3D_SDK_VERSION, &directx9::IDirect3D9)))
	{
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}

	D3DPRESENT_PARAMETERS Params = { 0 };
	Params.Windowed = TRUE;
	Params.SwapEffect = D3DSWAPEFFECT_DISCARD;
	Params.hDeviceWindow = overlay_window::hwnd;
	Params.MultiSampleQuality = D3DMULTISAMPLE_NONE;
	Params.BackBufferFormat = D3DFMT_A8R8G8B8;
	Params.BackBufferWidth = rect.width();
	Params.BackBufferHeight = rect.height();
	Params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
	Params.EnableAutoDepthStencil = TRUE;
	Params.AutoDepthStencilFormat = D3DFMT_D16;
	Params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
	Params.FullScreen_RefreshRateInHz = D3DPRESENT_RATE_DEFAULT;
	if (FAILED(directx9::IDirect3D9->CreateDeviceEx(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, overlay_window::hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &Params, 0, &directx9::device))) {
		directx9::IDirect3D9->Release();
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}

	ImGui::CreateContext();
	ImPlot::CreateContext();
	if (!ImGui_ImplWin32_Init(overlay_window::hwnd))
	{
		ImGui::DestroyContext();
		ImPlot::DestroyContext();
		directx9::device->EndScene();
		directx9::device->Release();
		directx9::IDirect3D9->Release();
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}
	if (!ImGui_ImplDX9_Init(directx9::device))
	{
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();
		ImPlot::DestroyContext();
		directx9::device->EndScene();
		directx9::device->Release();
		directx9::IDirect3D9->Release();
		DestroyWindow(overlay_window::hwnd);
		UnregisterClass(title, overlay_window::hInstance);
		return false;
	}
	directx9::IDirect3D9->Release();


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

void overlay::render(const data::game& data)
{
	static auto show_menu = false;

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();
	draw(data, ImGui::GetBackgroundDrawList());

	if (GetAsyncKeyState(VK_INSERT) & 1)
	{
		show_menu = !show_menu;
		const auto style = show_menu ? WS_EX_TRANSPARENT | WS_EX_NOACTIVATE : WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
		SetWindowLong(overlay_window::hwnd, GWL_EXSTYLE, style);
	}
	if (show_menu)
		menu();

	ImGui::EndFrame();

	directx9::device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0f, 0);
	if (directx9::device->BeginScene() >= 0) {
		ImGui::Render();
		ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
		directx9::device->EndScene();
	}

	const auto result = directx9::device->Present(NULL, NULL, NULL, NULL);
	if (result == D3DERR_DEVICELOST && directx9::device->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
		ImGui_ImplDX9_InvalidateDeviceObjects();
		directx9::device->Reset(&directx9::params);
		ImGui_ImplDX9_CreateDeviceObjects();
	}
}

void overlay::destroy()
{
	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	if (directx9::device != NULL) {
		directx9::device->EndScene();
		directx9::device->Release();
	}
	if (directx9::IDirect3D9 != NULL) {
		directx9::IDirect3D9->Release();
	}
	DestroyWindow(overlay_window::hwnd);
	UnregisterClass(title, overlay_window::hInstance);
}