﻿#include "driver/driver.h"
#include <iostream>
#include <TlHelp32.h>
#include <array>
#include <fstream>
#include "overlay/overlay.hpp"
#include <iostream>
#include <thread>

void overlay_execute() {
	if (!overlay::create_overlay(L"Counter-Strike: Global Offensive"))
		return;

	MSG message;
	do
	{
		if (PeekMessageW(&message, overlay::overlay_window, 0, 0, PM_REMOVE)) {
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}

		if (overlay::begin()) {
			overlay::present();
			overlay::end();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	} while (message.message != WM_QUIT);

	return;
}

int main(int argc, char* argv[]) {
	std::cout << "Close this to disable DarkTool Overlay\n";
	std::thread overlay_thread(overlay_execute);
	overlay_thread.join();
	return 0;
}

/*
std::uint32_t find_process_by_id(const std::string& name)
{
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	auto found_process = false;
	if (!!Process32First(snap, &proc_entry)) {
		do {
			if (name == proc_entry.szExeFile) {
				found_process = true;
				break;
			}
		} while (!!Process32Next(snap, &proc_entry));
	}

	CloseHandle(snap);
	return found_process
		? proc_entry.th32ProcessID
		: 0;
}

void example()
{
	const auto connection = driver::connect();
	if (connection == INVALID_SOCKET)
	{
		std::cout << "Connection failed.\n";
		return;
	}

	// Loader spoofing
	driver::clean_piddbcachetable(connection);
	driver::clean_mmunloadeddrivers(connection);

	// Spoof drives
	driver::spoof_drives(connection);

	// Cheat related stuff
	const auto pid = find_process_by_id("notepad.exe");
	std::printf("Process id: %p.\n", pid);

	const auto base_address = driver::get_process_base_address(connection, pid);
	std::printf("Process base address: %p.\n", (void*)base_address);

	const auto dos_magic = driver::read<uint16_t>(connection, pid, base_address);
	std::printf("DOS signature: %X.\n", dos_magic);

	const auto aaa = driver::read<std::array<char, 6000>>(connection, pid, base_address);
	std::ofstream fout;
	fout.open("file.txt", std::ios::binary | std::ios::out);

	fout.write(aaa.data(), aaa.size());

	fout.close();
	driver::disconnect(connection);
}

int main()
{
	driver::initialize();

	example();

	driver::deinitialize();
	std::cin.get();
}*/