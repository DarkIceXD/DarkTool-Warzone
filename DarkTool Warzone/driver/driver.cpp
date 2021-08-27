#include "driver.h"
#include "server_shared.h"
#include <TlHelp32.h>
#pragma comment(lib, "Ws2_32")
#include <mutex>

static SOCKET connection;
static uint32_t _pid;
static std::mutex mtx;

static bool send_packet(
	const Packet& packet,
	uint64_t& out_result)
{
	std::lock_guard<std::mutex> lck(mtx);
	if (send(connection, (const char*)&packet, sizeof(Packet), 0) == SOCKET_ERROR)
		return false;

	Packet completion_packet{ };
	const auto result = recv(connection, (char*)&completion_packet, sizeof(Packet), 0);
	if (result < sizeof(PacketHeader) || !completion_packet.header.is_valid() || completion_packet.header.type != PacketType::packet_completed)
		return false;

	out_result = completion_packet.data.completed.result;
	return true;
}

static uint32_t copy_memory(
	const uint32_t	src_process_id,
	const uintptr_t src_address,
	const uint32_t	dest_process_id,
	const uintptr_t	dest_address,
	const size_t	size)
{
	Packet packet{ };
	packet.header.type = PacketType::packet_copy_memory;

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

void driver::initialize(const std::wstring_view& process)
{
	_pid = find_process_by_id(process);
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

uint32_t driver::pid()
{
	return _pid;
}

void driver::deinitialize()
{
	WSACleanup();
}

bool driver::connect()
{
	SOCKADDR_IN address{ };

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(server_ip);
	address.sin_port = htons(server_port);

	const auto sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
		return false;

	if (connect(sock, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
	{
		closesocket(sock);
		return false;
	}

	connection = sock;
	return true;
}

void driver::disconnect()
{
	closesocket(connection);
}

uint32_t driver::read_memory(const uintptr_t address, const uintptr_t buffer, const size_t size)
{
	return copy_memory(_pid, address, GetCurrentProcessId(), buffer, size);
}

uint32_t driver::write_memory(const uintptr_t address, const uintptr_t buffer, const size_t size)
{
	return copy_memory(GetCurrentProcessId(), buffer, _pid, address, size);
}

uint64_t driver::get_process_base_address()
{
	Packet packet{ };
	packet.header.type = PacketType::packet_get_base_address;

	auto& data = packet.data.get_base_address;
	data.process_id = _pid;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return result;

	return 0;
}

uint64_t driver::clean_piddbcachetable()
{
	Packet packet{ };
	packet.header.type = PacketType::packet_clean_piddbcachetable;

	auto& data = packet.data.clean_piddbcachetable;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return 1;

	return 0;
}

uint64_t driver::clean_mmunloadeddrivers()
{
	Packet packet{ };
	packet.header.type = PacketType::packet_clean_mmunloadeddrivers;

	auto& data = packet.data.clean_mmunloadeddrivers;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return 1;

	return 0;
}

uint64_t driver::spoof_drives()
{
	Packet packet{ };
	packet.header.type = PacketType::packet_spoof_drives;

	auto& data = packet.data.spoof_drives;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return 1;

	return 0;
}

uint64_t driver::get_peb()
{
	Packet packet{ };
	packet.header.type = PacketType::packet_get_peb;

	auto& data = packet.data.get_peb;
	data.process_id = _pid;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return result;

	return 0;
}
