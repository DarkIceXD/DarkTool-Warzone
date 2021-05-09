#pragma once
#include "server_shared.h"
#include "sockets.h"

namespace packet_handler {
	uint64_t handle(const Packet& packet);
	bool complete_request(const SOCKET client_connection, const uint64_t result);
}