﻿#include "driver.h"
#include "server_shared.h"

#pragma comment(lib, "Ws2_32")

static SOCKET connection;

static bool send_packet(
	const Packet& packet,
	uint64_t& out_result)
{
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

void driver::initialize()
{
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
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

uint32_t driver::read_memory(
	const uint32_t	process_id,
	const uintptr_t address,
	const uintptr_t buffer,
	const size_t	size)
{
	return copy_memory(process_id, address, GetCurrentProcessId(), buffer, size);
}

uint32_t driver::write_memory(
	const uint32_t	process_id,
	const uintptr_t address,
	const uintptr_t buffer,
	const size_t	size)
{
	return copy_memory(GetCurrentProcessId(), buffer, process_id, address, size);
}

uint64_t driver::get_process_base_address(const uint32_t process_id)
{
	Packet packet{ };
	packet.header.type = PacketType::packet_get_base_address;

	auto& data = packet.data.get_base_address;
	data.process_id = process_id;

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

uint64_t driver::get_peb(const uint32_t process_id)
{
	Packet packet{ };
	packet.header.type = PacketType::packet_get_peb;

	auto& data = packet.data.get_peb;
	data.process_id = process_id;

	uint64_t result = 0;
	if (send_packet(packet, result))
		return result;

	return 0;
}
