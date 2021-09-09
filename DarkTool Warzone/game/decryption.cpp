#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"
#include <iostream>

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

		RBX = readMemory<uint64_t>(imageBase + 0x16EC7BD8);
		if (RBX == 0) {
			return 0;
		}
		RAX -= 0x78;
		// movzx eax,al
		R8 = peb; // mov r8,gs:[rax]
		R8 = ~R8;
		RAX = 0xFCED13C467C6698B;
		RBX *= RAX;
		RAX = R8;
		RDX = 0x3844E7F6ED3E15BC;
		RAX = ~RAX;
		RBX += RAX;
		RAX = imageBase + 0x489FF96E;
		RAX = ~RAX;
		RBX += RAX;
		RAX = RBX;
		RAX >>= 0x17;
		RBX ^= RAX;
		RAX = RBX;
		RCX = 0x0;
		RAX >>= 0x2E;
		RAX ^= RBX;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= readMemory<uint64_t>(imageBase + 0x690F10E);
		RAX ^= RDX;
		RCX = _byteswap_uint64(RCX);
		RAX += R8;
		RBX = readMemory<uint64_t>(RCX + 0x15);
		RBX *= RAX;
		return RBX;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RAX = readMemory<uint64_t>(clientInfo + 0x9ED98);
		RBX = peb; // mov rbx,gs:[rcx]
		// test rax,rax
		// je 00007FF66F3E83AFh
		RCX = RBX;
		RCX = _rotl64(RCX, 0x24);
		RCX &= 0xF;
		// cmp rcx,0Eh
		// ja 00007FF66F3E8018h
		switch (RCX) {
		case 0: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			RCX = RAX;
			RCX >>= 0x16;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2C;
			RAX ^= RCX;
			RCX = 0xB1234B0689FEED1;
			RAX *= RCX;
			RCX = 0xD2BC4ACEA66D1E1B;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1F;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3E;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1E;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3C;
			RAX ^= RCX;
			RAX -= R11;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RDX = ~RDX;
			RCX = RBX - 0x315EB556;
			RCX += RAX;
			RCX ^= RBX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			return RAX;
		}
		case 1: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = R11 + 0x0FB6F;
			RCX += RBX;
			RAX ^= RCX;
			RAX ^= RBX;
			RCX = RAX;
			RCX >>= 0xE;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1C;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x38;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1F;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3E;
			RAX ^= RCX;
			RCX = 0x7B576C1A94E1013C;
			RAX ^= RCX;
			RCX = 0x29C69418290CCE35;
			RAX ^= RCX;
			RCX = 0x79FF5F0EEE20769;
			RAX *= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0x13);
			return RAX;
		}
		case 2: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R14 = imageBase + 0x1861;
			R15 = imageBase + 0xA40A;
			RCX = RAX;
			RCX >>= 0xA;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x14;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x28;
			RAX ^= RCX;
			RDX = 0x0;
			RCX = RBX;
			RCX *= R15;
			RDX = _rotl64(RDX, 0x10);
			RCX ^= RAX;
			RDX ^= R10;
			RDX = ~RDX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x18;
			RAX ^= RCX;
			RDX = RAX;
			RDX >>= 0x30;
			RDX ^= RAX;
			RAX = RBX;
			RAX *= R14;
			RAX += RDX;
			RCX = 0x706402F41DE52AC9;
			RAX *= RCX;
			RCX = 0xE602E1C4E2D078CB;
			RAX ^= RCX;
			RCX = 0x458C07C6BDFE04F8;
			RAX ^= RCX;
			return RAX;
		}
		case 3: {
			uint64_t RBP_NEG_0x78 = imageBase;
			R15 = imageBase + 0x4E080E42;
			RCX = imageBase + 0x34E2;
			RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
			R9 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RAX -= RBX;
			RCX = RBX;
			RCX = ~RCX;
			RCX *= R15;
			RAX ^= RCX;
			RCX = RBX;
			RCX *= RBP_NEG_0x78; // imul rcx,[rbp-78h]
			RAX += RCX;
			RCX = imageBase + 0x6A3E82E2;
			RAX += RCX;
			RCX = 0x6068B2883739B04F;
			RAX *= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0x13);
			RCX = RAX;
			RCX >>= 0x9;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x12;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			return RAX;
		}
		case 4: {
			R14 = imageBase + 0xD8F;
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = RAX;
			RCX >>= 0x19;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x32;
			RAX ^= RCX;
			RAX -= RBX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0x13);
			RAX *= RCX;
			RCX = 0x4C2B84E0CBA297A4;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = R14;
			RCX -= RBX;
			RAX ^= RCX;
			RCX = 0xBC823BB36FCCFC8F;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x21;
			RAX ^= RCX;
			return RAX;
		}
		case 5: {
			R11 = imageBase;
			RDX = imageBase + 0x13B45F2F;
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = RDX;
			RCX = ~RCX;
			RCX ^= RBX;
			RAX -= RCX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RCX = R11 + 0x0A1A;
			RDX ^= R10;
			RCX += RBX;
			RDX = ~RDX;
			RDX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RDX;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x4;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x8;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0x6D1F5C7319C7A591;
			RAX ^= RCX;
			RCX = 0x6DFC846362600625;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x1C;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x38;
			RAX ^= RCX;
			RCX = 0x456991416BCB2285;
			RAX *= RCX;
			return RAX;
		}
		case 6: {
			R14 = imageBase + 0x59621C27;
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = RAX;
			RCX >>= 0x14;
			RAX ^= RCX;
			RCX = RAX;
			RDX = 0x0;
			RCX >>= 0x28;
			RCX ^= RAX;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RDX = ~RDX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RCX = 0xAB63115C0296DC39;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0xB;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x16;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2C;
			RAX ^= RCX;
			RAX ^= RBX;
			RCX = RBX;
			RCX = ~RCX;
			RCX *= R14;
			RAX += RCX;
			RCX = 0x19E2C01FE567D3E5;
			RAX += RCX;
			return RAX;
		}
		case 7: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			RDX = imageBase + 0x4F18;
			RCX = RAX;
			RCX >>= 0x21;
			RAX ^= RCX;
			RAX ^= RBX;
			RCX = 0x217CBC019ADD6CED;
			RAX *= RCX;
			RCX = RBX + 1;
			RCX *= RDX;
			RAX += RCX;
			RCX = 0xA975C5DE862ED14F;
			RAX *= RCX;
			RDX = 0x0;
			RCX = RAX;
			RDX = _rotl64(RDX, 0x10);
			RAX = 0x5C0E908CFA00E3B9;
			RCX ^= RAX;
			RDX ^= R10;
			RDX = ~RDX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RCX = R11 + 0x76725DFF;
			RCX += RBX;
			RAX += RCX;
			return RAX;
		}
		case 8: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RCX = RAX;
			RDX ^= R10;
			RAX = 0x826D4CD7053A3B0F;
			RDX = ~RDX;
			RCX ^= RAX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RDX = imageBase + 0x2566DC61;
			RAX ^= R11;
			RCX = RAX;
			RCX >>= 0x1D;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3A;
			RAX ^= RCX;
			RAX -= RBX;
			RCX = 0x6E136F54C0304293;
			RAX *= RCX;
			RCX = RBX;
			RCX *= RDX;
			RCX += R11;
			RAX -= RCX;
			return RAX;
		}
		case 9: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			RAX ^= R11;
			RAX += RBX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RCX = imageBase + 0x89E4;
			RAX += RCX;
			RDX ^= R10;
			RDX = ~RDX;
			RCX = RAX;
			RCX >>= 0x21;
			RCX ^= RAX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RCX = 0xA66D52587A5A7083;
			RAX *= RCX;
			RAX += R11;
			RCX = 0x640CAAE5A2282E05;
			RAX ^= RCX;
			RCX = 0xF24051F81CDED63F;
			RAX ^= RCX;
			return RAX;
		}
		case 10: {
			uint64_t RBP_NEG_0x80 = imageBase;
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			R15 = imageBase + 0x4DB9D2C7;
			RCX = 0x57F82B1F124C3C35;
			RBP_NEG_0x80 = RCX; // mov [rbp-80h],rcx
			RCX = R15;
			RCX = ~RCX;
			RCX ^= RBX;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x1B;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x36;
			RAX ^= RCX;
			RCX = RBX;
			RCX -= R11;
			RAX += RBX;
			RCX -= 0x78483513;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0x13);
			RCX *= RBP_NEG_0x80; // imul rcx,[rbp-80h]
			RAX *= RCX;
			RCX = 0x7F2AE5C1F19DABBD;
			RAX ^= RCX;
			return RAX;
		}
		case 11: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0x13);
			RCX = 0x5BD8DE6B9D51D117;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x7;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0xE;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1C;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x38;
			RCX ^= RAX;
			RAX = 0x883E09AE2FC1878D;
			RCX ^= R11;
			RCX *= RAX;
			RAX = 0x376E32D2ACDB7105;
			RAX += RCX;
			RAX += RBX;
			RCX = RAX;
			RCX >>= 0xA;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x14;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x28;
			RAX ^= RCX;
			return RAX;
		}
		case 12: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RCX = RAX;
			RCX >>= 0x8;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0x4411B7D7BD0746A1;
			RAX *= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0x13);
			RAX *= RCX;
			RCX = 0x374CACF0E3108651;
			RAX -= R11;
			RAX ^= RCX;
			RAX ^= RBX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0x4E3C89CFA73560D5;
			RAX *= RCX;
			return RAX;
		}
		case 13: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			R15 = imageBase + 0x1957CA6F;
			RCX = 0x7B7BDB1C95BBEB93;
			RAX *= RCX;
			RAX -= R11;
			RAX += 0xFFFFFFFFFFFFFD6C;
			RAX += RBX;
			RCX = 0x42A678B1F30FA0F3;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x12;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x4;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x8;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0x13);
			RCX = 0x1E3DEFA0B52408A8;
			RAX += RCX;
			RCX = RBX;
			RCX *= R15;
			RAX ^= RCX;
			return RAX;
		}
		case 14: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F13D);
			R11 = imageBase;
			R15 = imageBase + 0x2A03;
			RCX = R11 + 0x0FA06;
			RCX += RBX;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x11;
			RAX ^= RCX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RCX = RAX;
			RDX ^= R10;
			RCX >>= 0x22;
			RDX = ~RDX;
			RCX ^= RAX;
			RAX = readMemory<uint64_t>(RDX + 0x13);
			RAX *= RCX;
			RCX = 0xF3E6DE9C18BDD449;
			RAX *= RCX;
			RAX ^= RBX;
			RAX ^= R15;
			RCX = 0x4439F2BD595FD830;
			RAX ^= RCX;
			RCX = 0x756C97787209CC0;
			RAX -= RCX;
			RCX = RAX;
			RCX >>= 0x26;
			RAX ^= RCX;
			return RAX;
		}
		case 15: {
			R14 = imageBase + 0x3D88;
			R15 = imageBase + 0x5DA;
			R11 = readMemory<uint64_t>(imageBase + 0x690F13D);
			RDX = R15;
			RDX = ~RDX;
			RCX = RBX + 1;
			RCX *= R14;
			RCX += RAX;
			RAX = RBX + 1;
			RDX += RCX;
			RCX = 0x9FA0F66FBCE5D1B8;
			RAX += RDX;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0x1F8175F85982B5D5;
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R11;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0x13);
			RCX = 0x6FBF45724BDD188F;
			RAX *= RCX;
			RAX ^= RBX;
			return RAX;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RDX = readMemory<uint64_t>(imageBase + 0x151B0C08);
		if (RDX == 0) {
			return 0;
		}
		R8 = peb; // mov r8,gs:[rax]
		// test rdx,rdx
		// je 00007FF66F6D6E3Ah
		RAX = R8;
		RAX = _rotl64(RAX, 0x2B);
		RAX &= 0xF;
		// cmp rax,0Eh
		// ja 00007FF66F6D6A2Dh
		switch (RAX) {
		case 0: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = 0x36F1E3CBC946FE37;
			RDX *= RAX;
			RAX = 0x3DD00D6C20FFEE9E;
			RDX -= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RAX = readMemory<uint64_t>(RAX + 0x7);
			RDX *= RAX;
			RDX -= R8;
			RAX = imageBase;
			RAX += 0x23C3418D;
			RAX += R8;
			RDX += RAX;
			RAX = 0x44B14DB3F549C9B9;
			RDX -= RAX;
			RAX = RDX;
			RAX >>= 0x26;
			RDX ^= RAX;
			RAX = imageBase;
			RDX += RAX;
			return RDX;
		}
		case 1: {
			uint64_t RSP_0x78 = imageBase;
			// pushfq
			// push rbx
			// pop rbx
			// pop rbx
			// popfq
			RAX = imageBase + 0x345D5A97;
			RSP_0x78 = RAX; // mov [rsp+78h],rax
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = imageBase;
			RAX += 0x19251E0B;
			RAX += R8;
			RDX += RAX;
			RAX = RDX;
			RAX >>= 0x14;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x28;
			RDX ^= RAX;
			RAX = 0x6036A113BF807BB9;
			RDX *= RAX;
			RAX = 0x5905E809C1A78148;
			RDX ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = 0x88980DA7EF38BCFB;
			RDX *= RAX;
			RAX = R8;
			RAX *= RSP_0x78; // imul rax,[rsp+78h]
			RDX = RDX + RAX * 2;
			return RDX;
		}
		case 2: {
			R14 = imageBase + 0xFEE1;
			R15 = imageBase + 0x3D44;
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RDX ^= R8;
			RDX ^= R14;
			RAX = R8;
			RAX = ~RAX;
			RDX += RAX;
			RDX += R15;
			RAX = RDX;
			RAX >>= 0x21;
			RDX ^= RAX;
			RAX = 0x4F8044F340F684EF;
			RDX *= RAX;
			RAX = imageBase;
			RDX -= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = RDX;
			RCX ^= RBX;
			RDX = 0xAAAC77004BFB2B5A;
			RCX = ~RCX;
			RAX ^= RDX;
			RDX = readMemory<uint64_t>(RCX + 0x7);
			RDX *= RAX;
			return RDX;
		}
		case 3: {
			R14 = imageBase + 0x1B91;
			R15 = imageBase + 0xFCF4;
			R10 = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = RDX;
			RAX >>= 0x20;
			RDX ^= RAX;
			RAX = 0xB7FCF9F7F93C4DC1;
			RDX *= RAX;
			RAX = R8;
			RAX *= R15;
			RDX += RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RAX = readMemory<uint64_t>(RAX + 0x7);
			RDX *= RAX;
			RAX = 0xE5C4B713BD7F2777;
			RDX ^= RAX;
			RAX = 0xD5FA8F8FA69871A1;
			RDX *= RAX;
			RAX = R8;
			RAX = ~RAX;
			RAX ^= R14;
			RDX -= RAX;
			RDX += R8;
			return RDX;
		}
		case 4: {
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			R15 = imageBase + 0x5CE54BB0;
			R12 = imageBase + 0x3F6B;
			RAX = RDX;
			RAX >>= 0x15;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x2A;
			RDX ^= RAX;
			RAX = R8;
			RAX ^= R15;
			RDX += RAX;
			RAX = RDX;
			RAX >>= 0x1F;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x3E;
			RDX ^= RAX;
			RAX = 0x8CE861A897AF1DF1;
			RDX *= RAX;
			RDX ^= R8;
			RDX -= R8;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RDX += R12;
			RCX = R8;
			RCX = ~RCX;
			RDX += RCX;
			return RDX;
		}
		case 5: {
			// push rdx
			// pushfq
			// pop rdx
			// popfq
			// pop rdx
			RCX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = RDX;
			RAX >>= 0x11;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x22;
			RDX ^= RAX;
			RAX = 0x34F43C73E828AFD4;
			RDX -= RAX;
			RAX = RDX;
			RAX >>= 0x21;
			RDX ^= RAX;
			RAX = 0xB25B0F70C734D221;
			RDX *= RAX;
			RDX ^= R8;
			RAX = 0x3AEBE5DAD428EB23;
			RDX += RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RCX;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = RDX;
			RAX >>= 0x1F;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x3E;
			RDX ^= RAX;
			return RDX;
		}
		case 6: {
			R9 = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = 0x7202DDAD1E6C8915;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x24;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x17;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x2E;
			RDX ^= RAX;
			RAX = 0x559C8C971154BA35;
			RDX *= RAX;
			RAX = imageBase;
			RDX += RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R9;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = RDX;
			RAX >>= 0xB;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x16;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x2C;
			RDX ^= RAX;
			RAX = 0x4A243E201FC624B4;
			RDX ^= RAX;
			return RDX;
		}
		case 7: {
			uint64_t RSP_0x48 = imageBase;
			// push rbx
			// pushfq
			// pop rbx
			// popfq
			// pop rbx
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = 0xFFC655859F2357CB;
			R15 = imageBase + 0xB227;
			RSP_0x48 = RAX; // mov [rsp+48h],rax
			RAX = 0xA47C1B4F283C7A51;
			RDX *= RAX;
			RAX = 0x5F828165B9BF0F34;
			RDX ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RAX = readMemory<uint64_t>(RAX + 0x7);
			RAX *= RSP_0x48; // imul rax,[rsp+48h]
			RDX *= RAX;
			RAX = RDX;
			RAX >>= 0x15;
			RDX ^= RAX;
			RAX = R8;
			RCX = RDX;
			RAX ^= R15;
			RCX >>= 0x2A;
			RDX ^= RCX;
			RDX -= RAX;
			RAX = RDX;
			RAX >>= 0x10;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x20;
			RDX ^= RAX;
			RAX = imageBase;
			RDX ^= RAX;
			return RDX;
		}
		case 8: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F22B);
			R12 = imageBase + 0x57D77D98;
			RAX = imageBase;
			RDX -= RAX;
			RAX = 0x69641E05B6B1240B;
			RDX *= RAX;
			RAX = R8;
			RAX = ~RAX;
			RAX += R12;
			RDX ^= RAX;
			RAX = imageBase;
			RDX ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = 0x5438F0F86F0913E3;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x9;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x12;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x24;
			RDX ^= RAX;
			RAX = 0x7390C908AE264945;
			RDX -= RAX;
			return RDX;
		}
		case 9: {
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			R12 = imageBase + 0x6015;
			RAX = imageBase;
			RDX += RAX;
			RAX = RDX;
			RDX = 0xF41CEA57D99619DF;
			RAX *= RDX;
			RDX = R12;
			RAX += R8;
			RDX = ~RDX;
			RDX += RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = RDX;
			RCX ^= RBX;
			RAX >>= 0x22;
			RCX = ~RCX;
			RAX ^= RDX;
			RDX = readMemory<uint64_t>(RCX + 0x7);
			RDX *= RAX;
			RAX = 0xEA36F55CAEF3C2B5;
			RDX *= RAX;
			RCX = R8;
			RCX = ~RCX;
			RAX = imageBase + 0x3595365D;
			RAX = ~RAX;
			RCX *= RAX;
			RAX = RDX;
			RDX = 0x3360BBB642BDF19;
			RAX *= RDX;
			RDX = RCX;
			RDX ^= RAX;
			return RDX;
		}
		case 10: {
			R12 = imageBase + 0x27BCD430;
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = 0xF52A9FBB3639D4C3;
			RDX ^= RAX;
			RAX = 0xC0ED038D4BFB6909;
			RDX *= RAX;
			RAX = 0x8D4FF9101E7E7075;
			RDX ^= RAX;
			RAX = imageBase;
			RDX -= RAX;
			RDX += 0xFFFFFFFFCA03C931;
			RDX += R8;
			RAX = RDX;
			RAX >>= 0x21;
			RDX ^= RAX;
			RAX = imageBase;
			RDX += RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = R8;
			RAX *= R12;
			RDX -= RAX;
			return RDX;
		}
		case 11: {
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			R15 = imageBase + 0x6AF;
			RAX = 0x33517081EAA8C760;
			RDX ^= RAX;
			RAX = 0x221DBCDAFC7B6BD;
			RDX *= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RCX = R8;
			RAX = R15;
			RAX = ~RAX;
			RCX = ~RCX;
			RCX += RAX;
			RAX = 0x239ADAB24A836CC4;
			RAX += RDX;
			RDX = RCX;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0xD;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x1A;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x34;
			RDX ^= RAX;
			return RDX;
		}
		case 12: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RAX = RDX;
			RAX >>= 0x4;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x8;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x10;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x20;
			RDX ^= RAX;
			RAX = 0xD000F6420E1E0C8B;
			RDX *= RAX;
			RAX = RDX;
			RAX >>= 0x6;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0xC;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x18;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x30;
			RDX ^= RAX;
			RAX = imageBase;
			RDX -= RAX;
			RDX ^= R8;
			RAX = imageBase;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x23;
			RDX ^= RAX;
			return RDX;
		}
		case 13: {
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			R15 = imageBase + 0xBC6C;
			RDX += R8;
			RAX = R8;
			RAX *= R15;
			RDX += RAX;
			RAX = 0xB5DD4A977C950F42;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x14;
			RDX ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = RDX;
			RCX ^= RBX;
			RAX >>= 0x28;
			RCX = ~RCX;
			RAX ^= RDX;
			RDX = readMemory<uint64_t>(RCX + 0x7);
			RDX *= RAX;
			RAX = imageBase;
			RDX += RAX;
			RAX = 0xDC843224A1D78393;
			RDX *= RAX;
			return RDX;
		}
		case 14: {
			R10 = readMemory<uint64_t>(imageBase + 0x690F22B);
			RDX ^= R8;
			RAX = 0x8C4806715ADD71E5;
			RDX *= RAX;
			RAX = RDX;
			RAX >>= 0x22;
			RDX ^= RAX;
			RAX = 0x5E124860BE81FDB2;
			RDX ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RDX *= readMemory<uint64_t>(RAX + 0x7);
			RDX -= R8;
			RAX = RDX;
			RAX >>= 0x1B;
			RDX ^= RAX;
			RAX = RDX;
			RAX >>= 0x36;
			RDX ^= RAX;
			RAX = 0x67881686B75D4366;
			RDX -= RAX;
			return RDX;
		}
		case 15: {
			uint64_t RBP_0x1E0 = imageBase;
			RBX = readMemory<uint64_t>(imageBase + 0x690F22B);
			RAX = RDX;
			RAX >>= 0x23;
			RDX ^= RAX;
			RAX = imageBase + 0x3C07;
			RAX -= R8;
			RDX ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RBX;
			RAX = ~RAX;
			RCX = readMemory<uint64_t>(RAX + 0x7);
			RCX *= RDX;
			RDX = imageBase;
			RCX += R8;
			RDX += 0xBE16;
			RAX = 0xB380D5156A56FEDA;
			RAX += RCX;
			RDX += RAX;
			RAX = imageBase;
			RDX -= RAX;
			RAX = R8;
			RAX -= RBP_0x1E0; // sub rax,[rbp+1E0h]
			RDX += 0xFFFFFFFFDC4D1856;
			RAX -= 0x567B;
			RDX += R8;
			RDX ^= RAX;
			RAX = 0xD1C1845C518DDFD3;
			RDX *= RAX;
			return RDX;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RBX = index;
		RCX = RBX * 0x13C8;
		RAX = 0xD5E2CF5BD367D605;
		R11 = imageBase;
		RAX = _umul128(RAX, RCX, &RDX);
		R10 = 0xA04EDEF13CB4001B;
		RDX >>= 0xD;
		RAX = RDX * 0x264D;
		RCX -= RAX;
		RAX = 0x7F0003F8001FC001;
		R8 = RCX * 0x264D;
		RAX = _umul128(RAX, R8, &RDX);
		RDX >>= 0xD;
		RAX = RDX * 0x4081;
		R8 -= RAX;
		RAX = 0x807062560B49E0A5;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = 0x8888888888888889;
		RDX >>= 0xA;
		RCX = RDX * 0x7F9;
		RAX = _umul128(RAX, R8, &RDX);
		R8 <<= 0x5;
		RDX >>= 0x3;
		RCX += RDX;
		RAX = RCX * 0x1E;
		R8 -= RAX;
		RAX = readMemory<uint16_t>(R8 + R11 + 0x691B6B0);
		R8 = RAX * 0x13C8;
		RAX = R10;
		RAX = _umul128(RAX, R8, &RDX);
		RCX = R8;
		RAX = R10;
		RCX -= RDX;
		RCX >>= 0x1;
		RCX += RDX;
		RCX >>= 0xD;
		RCX = RCX * 0x275B;
		R8 -= RCX;
		R9 = R8 * 0x3893;
		RAX = _umul128(RAX, R9, &RDX);
		RAX = R9;
		RAX -= RDX;
		RAX >>= 0x1;
		RAX += RDX;
		RAX >>= 0xD;
		RAX = RAX * 0x275B;
		R9 -= RAX;
		RAX = 0xD39EA9C56972BF79;
		RAX = _umul128(RAX, R9, &RDX);
		RCX = R9;
		R9 &= 0x3;
		RDX >>= 0xC;
		RAX = RDX * 0x135B;
		RCX -= RAX;
		RAX = R9 + RCX * 4;
		RSI = readMemory<uint16_t>(R11 + RAX * 2 + 0x692A5E0);
		return RSI;
	}
}

struct ref_def_key
{
	int ref0, ref1, ref2;
};

uintptr_t decryption::get_ref_def(const uint64_t imageBase, const uintptr_t ref_def_ptr)
{
	const auto crypt = driver::read<ref_def_key>(imageBase + ref_def_ptr);

	const uint32_t lower = crypt.ref0 ^ (crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr)) * ((crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr)) + 2);
	const uint32_t upper = crypt.ref1 ^ (crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr + 0x4)) * ((crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr + 0x4)) + 2);

	return (uint64_t)upper << 32 | lower;
}

uint64_t decryption::get_visible_base(const uint64_t imageBase, const uint64_t visible_offset, const uint64_t distribute)
{
	const uint64_t about_visible = imageBase + visible_offset;
	const auto vis_base = driver::read<uint64_t>(imageBase + distribute);
	if (!vis_base)
		return 0;

	for (int32_t i = 4000; i >= 0; --i)
	{
		const uint64_t n_index = (i + (i << 2)) << 0x6;
		const uint64_t vis_base_ptr = vis_base + n_index;
		const auto cmp_function = driver::read<uint64_t>(vis_base_ptr + 0x90);
		if (!cmp_function)
			continue;

		if (cmp_function == about_visible)
		{
			const auto visible_list = driver::read<uint64_t>(vis_base_ptr + 0x108);
			std::cout << i << '\n';
			return visible_list;
		}
	}
	return 0;
}