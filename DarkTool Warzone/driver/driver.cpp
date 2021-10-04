#include "driver.h"
#include "server_shared.h"
#include <TlHelp32.h>
#include <mutex>

static uint32_t _pid;
static packet* _packet;
static HANDLE start;
static HANDLE finished;

static std::mutex mtx;

static uint32_t find_process_by_id(const std::wstring_view& name)
{
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	if (!!Process32First(snap, &proc_entry)) {
		do {
			if (name == proc_entry.szExeFile) {
				CloseHandle(snap);
				return proc_entry.th32ProcessID;
			}
		} while (!!Process32Next(snap, &proc_entry));
	}

	CloseHandle(snap);
	return 0;
}

static packet* get_packet()
{
	static auto shared = OpenFileMappingA(FILE_MAP_WRITE, FALSE, "Global\\DarkShare");
	static packet* packet_ = (packet*)MapViewOfFile(shared, FILE_MAP_WRITE, 0, 0, sizeof(packet));
	/*if (packet)
		UnmapViewOfFile(packet);

	packet = (Packet*)MapViewOfFile(shared, FILE_MAP_WRITE, 0, 0, sizeof(Packet));
	*/
	return packet_;
}

static int create_shared_events() {
	start = CreateEvent(NULL, FALSE, FALSE, L"Global\\DarkStart");
	if (!start)
		return GetLastError();

	finished = CreateEvent(NULL, FALSE, FALSE, L"Global\\DarkFinished");
	if (!finished)
		return GetLastError();

	return 0;
}

static bool send_packet(const packet& packet, uint64_t& out)
{
	std::lock_guard lck(mtx);
	*_packet = packet;

	if (!ResetEvent(finished))
		return false;

	if (!SetEvent(start))
		return false;

	WaitForSingleObject(finished, INFINITE);
	out = _packet->data.completed.result;
	return true;
}

static uint32_t copy_memory(const uint32_t src_process_id, const uintptr_t src_address, const uint32_t dest_process_id, const uintptr_t dest_address, const size_t size)
{
	packet packet;
	packet.type = packet::type::copy_memory;

	auto& data = packet.data.copy_memory;
	data.src_process_id = src_process_id;
	data.src_address = uint64_t(src_address);
	data.dest_process_id = dest_process_id;
	data.dest_address = uint64_t(dest_address);
	data.size = uint64_t(size);

	uint64_t result = 0;
	if (send_packet(packet, result))
		return uint32_t(result);

	return 0;
}

driver::status driver::initialize(const std::string_view& process)
{
	if (create_shared_events())
		return driver::status::events_failed;

	std::wstring wc(process.size(), L'#');
	size_t ret;
	mbstowcs_s(&ret, &wc[0], process.size() + 1, process.data(), process.size());
	_pid = find_process_by_id(wc);
	if (!_pid)
		return driver::status::process_not_found;

	_packet = get_packet();
	if (!_packet)
		return driver::status::driver_connection_failed;

	return driver::status::success;
}

uint32_t driver::pid()
{
	return _pid;
}

void driver::deinitialize()
{

}

uint64_t driver::get_base()
{
	packet packet;
	packet.type = packet::type::get_base;

	auto& data = packet.data.get_base;
	data.process_id = _pid;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return result;

	return 0;
}

uint64_t driver::get_peb()
{
	packet packet;
	packet.type = packet::type::get_peb;

	auto& data = packet.data.get_peb;
	data.process_id = _pid;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return result;

	return 0;
}

uint32_t driver::read_memory(const uintptr_t address, const uintptr_t buffer, const size_t size)
{
	return copy_memory(_pid, address, GetCurrentProcessId(), buffer, size);
}

uint32_t driver::write_memory(const uintptr_t address, const uintptr_t buffer, const size_t size)
{
	return copy_memory(GetCurrentProcessId(), buffer, _pid, address, size);
}