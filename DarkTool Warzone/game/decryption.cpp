#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

typedef unsigned __int64 QWORD;

uint64_t decryption::client_info(const uint64_t encrypted_address, const uint64_t peb)
{
	uint64_t RAX = 0, RBX = 0, RCX = 0, RDX = 0, R8 = 0, RDI = 0, R9 = 0, R10 = 0, R11 = 0, R12 = 0, R13 = 0, R14 = 0, RSI = 0, RSP = 0, RBP = 0;
	RBX = encrypted_address;
	if (!RBX)
		return 0;

	R8 = globals::base;
	RCX = peb;
	RCX = (~RCX);
	// test rbx,rbx
	// je short 000000000205FC31h
	RAX = globals::base;
	RDX = globals::base + 0xE9D;
	RAX -= RDX;
	RCX += RBX;
	RAX = 0; // Special case
	RCX += R8;
	RAX = _rotl64(RAX, 0x10);
	RDX = 0xD0FDC0E5AC56A3F1;
	RAX ^= driver::read<uintptr_t>(globals::base + 0x68FE0DC);
	RCX *= RDX;
	RAX = _byteswap_uint64(RAX);
	RDX = 0x7C09AF42D8BF321D;
	RCX += RDX;
	RAX = driver::read<uintptr_t>(RAX + 0x17);
	RAX *= RCX;
	RBX = RAX;
	RBX >>= 0x27;
	RBX ^= RAX;
	RBX += R8;
	return RBX;
}


uint64_t decryption::client_base(const uint64_t encrypted_address, const uint64_t peb)
{
	uint64_t RAX = globals::base, RBX = globals::base, RCX = globals::base, RDX = globals::base, R8 = globals::base, RDI = globals::base, R9 = globals::base, R10 = globals::base, R11 = globals::base, R12 = globals::base, R13 = globals::base, R14 = globals::base, R15 = globals::base, RSI = globals::base, RSP = globals::base, RBP = globals::base;
	RAX = encrypted_address;
	if (!RAX)
		return 0;
	RDI = peb;
	// test rax,rax
	// je near ptr 00000000020648E4h
	RCX = RDI;
	RCX >>= 0x17;
	// and ecx,0Fh
	RCX &= 0xF;
	switch (RCX)
	{
	case 0:
	{
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= driver::read<uintptr_t>(RCX + 0x11);
		RCX = globals::base;
		RAX += RCX;
		RCX = 0x5CD525BAF45D4153;
		RAX *= RCX;
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
		RCX = 0x3E9F9DBB6E66EB1A;
		RAX ^= RCX;
		RCX = globals::base;
		RAX -= RCX;
		RAX += 0xFFFFFFFF856D9D0D;
		RAX += RDI;
		RCX = RAX;
		RCX >>= 0x6;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xC;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x18;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x30;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xE;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1C;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x38;
		RAX ^= RCX;
		return RAX;
	}
	case 1:
	{
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x64C85167;
		RDX = RDI;
		RDX = (~RDX);
		RCX = globals::base + 0x4224;
		RCX = (~RCX);
		RDX *= RCX;
		RCX = 0xACCE08093FB3EFFD;
		RAX ^= RDX;
		RAX *= RCX;
		RCX = 0x5FB21A878C77BA33;
		RAX += RCX;
		RCX = R15;
		RCX = (~RCX);
		RCX += RDI;
		RAX ^= RCX;
		RCX = 0x22C2431C8FB82D9B;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x1C;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x38;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x14;
		RAX ^= RCX;
		RCX = RAX;
		// mov rdx,[rbp+0E8h]
		RDX -= RSI;
		RCX >>= 0x28;
		RDX = 0; // Special case
		RCX ^= RAX;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = driver::read<uintptr_t>(RDX + 0x11);
		RAX *= RCX;
		return RAX;
	}
	case 2:
	{
		RBX = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		RCX = 0xD6D9DEEDA5248D76;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x11;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x22;
		RAX ^= RCX;
		R8 = RDI;
		R8 = (~R8);
		// mov r9,[rbp+0E8h]
		R9 -= RSI;
		R9 = 0; // Special case
		R9 = _rotl64(R9, 0x10);
		RCX = globals::base + 0x2EC9;
		R9 ^= RBX;
		RDX = 0xDDE2E61B691384A0;
		RDX += RAX;
		RCX = (~RCX);
		RDX ^= R8;
		RAX = globals::base + 0x20F5092D;
		RAX ^= RDX;
		RAX += R8;
		RCX += RAX;
		R9 = _byteswap_uint64(R9);
		RAX = driver::read<uintptr_t>(R9 + 0x11);
		RAX *= RCX;
		RAX ^= RDI;
		RCX = 0x565E27B475312525;
		RAX *= RCX;
		return RAX;
	}
	case 3:
	{
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		R11 = globals::base + 0x7D269E03;
		RCX = 0xB179BC20C4853E9B;
		RAX *= RCX;
		RCX = globals::base;
		RAX -= RCX;
		RCX = 0x4A9F7DDA7B6600D7;
		RAX -= RCX;
		RCX = RAX;
		RCX >>= 0x22;
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
		// mov rdx,[rbp+0E8h]
		RCX = 0x67EE65DA588AACB0;
		RCX += RAX;
		RDX -= RSI;
		RDX = 0; // Special case
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = driver::read<uintptr_t>(RDX + 0x11);
		RAX *= RCX;
		RCX = RDI;
		RCX ^= R11;
		RAX -= RCX;
		return RAX;
	}
	case 4:
	{
		RSI = globals::base + 0x6AC;
		R11 = globals::base + 0x379408E5;
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RSP = 0x62E007A4AB5B56AB;
		RCX *= RSP;
		RAX *= RCX;
		RCX = RDI;
		RCX = (~RCX);
		RCX ^= R11;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x15;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x2A;
		RAX ^= RCX;
		RAX ^= RDI;
		RCX = 0xC1E61306CF319D97;
		RAX *= RCX;
		RCX = 0xF6A67E73491A1EFB;
		RCX -= globals::base;
		RAX += RCX;
		return RAX;
	}
	case 5:
	{
		RSI = globals::base + 0x6AC;
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = globals::base;
		RAX = RAX + RCX * 0x2;
		RAX ^= RCX;
		RCX = 0x76E88693C2A89DC9;
		RAX *= RCX;
		RCX = globals::base;
		RAX ^= RCX;
		// mov rdx,[rbp+0E8h]
		RDX -= RSI;
		RDX = 0; // Special case
		RCX = RDI + RAX;
		RDX = _rotl64(RDX, 0x10);
		RAX = globals::base + 0x2D9B;
		RCX += RAX;
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = driver::read<uintptr_t>(RDX + 0x11);
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x26;
		RAX ^= RCX;
		return RAX;
	}
	case 6:
	{
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x25792B82;
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = globals::base;
		RDX = RCX + 0x44E66251;
		RCX += RAX;
		RDX += RDI;
		RDX ^= RCX;
		RCX = RDX;
		RAX = RDX;
		RCX >>= 0xE;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1C;
		RAX ^= RCX;
		RDX = globals::base + 0x3ED51D49;
		RCX = RAX;
		RCX >>= 0x38;
		RAX ^= RCX;
		RCX = RDI;
		RCX ^= RDX;
		RAX -= RCX;
		RCX = RDI;
		RCX *= R15;
		RAX ^= RCX;
		RCX = globals::base;
		RAX += RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= driver::read<uintptr_t>(RCX + 0x11);
		RCX = 0xD821E1F8F10CC0E5;
		RAX *= RCX;
		return RAX;
	}
	case 7:
	{
		RSI = globals::base + 0x6AC;
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = globals::base;
		RAX += RCX;
		RCX = 0xCDD63885C351FBB5;
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x28;
		RAX ^= RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RBP = 0xD86054F77497C21F;
		RCX *= RBP;
		RAX *= RCX;
		RCX = 0xE9FBCF5BFD0D9235;
		RAX *= RCX;
		RCX = globals::base + 0x2B58;
		RCX -= RDI;
		RAX += RCX;
		RAX += RDI;
		return RAX;
	}
	case 8:
	{
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x261CDD99;
		RBX = globals::base + 0x6877DAE4;
		RCX = 0x74F032451C0F3AAB;
		RAX += RCX;
		RCX = 0x91AAF2F4B147480D;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x28;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xD;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1A;
		RAX ^= RCX;
		RDX = RAX;
		RDX >>= 0x34;
		RDX ^= RAX;
		RAX = RDI;
		RAX ^= RBX;
		RCX = 0xAE4F1D68CD4FA409;
		RAX += RDX;
		RAX *= RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= driver::read<uintptr_t>(RCX + 0x11);
		RCX = R15;
		RCX = (~RCX);
		RCX += RDI;
		RAX ^= RCX;
		return RAX;
	}
	case 9:
	{
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x19301967;
		RCX = 0xA03A5CAEA4279C49;
		RAX *= RCX;
		RCX = 0x71C02514CF8A9DA8;
		RAX += RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= driver::read<uintptr_t>(RCX + 0x11);
		RCX = 0x9EDB961AC1CA708C;
		RAX ^= RCX;
		RAX += R15;
		RDX = RDI;
		RDX = (~RDX);
		RAX += RDX;
		RCX = RAX;
		RCX >>= 0x10;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x20;
		RAX ^= RCX;
		RCX = globals::base;
		RAX ^= RCX;
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
		RAX ^= RCX;
		return RAX;
	}
	case 10:
	{
		RSI = globals::base + 0x6AC;
		RBX = globals::base + 0x1A015076;
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = RAX;
		RCX >>= 0x1C;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x38;
		RAX ^= RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= driver::read<uintptr_t>(RCX + 0x11);
		RCX = RAX;
		RCX >>= 0x15;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x2A;
		RAX ^= RCX;
		RCX = RDI;
		RCX ^= RBX;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0xC;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x18;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x30;
		RAX ^= RCX;
		RCX = 0x11B19D41A5FE8AE1;
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x26;
		RAX ^= RCX;
		RCX = globals::base;
		RAX ^= RCX;
		return RAX;
	}
	case 11:
	{
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x78378FCB;
		RBX = globals::base + 0x7998;
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = globals::base;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x1F;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x3E;
		RAX ^= RCX;
		RCX = 0x41CF04660260443;
		RAX += RCX;
		RCX = 0x740D13B79DE35AE6;
		RAX += RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RAX *= RCX;
		RAX ^= RDI;
		RAX ^= RBX;
		RCX = 0x7712A4C8F3E6DF2D;
		RAX *= RCX;
		RCX = RDI;
		RCX = (~RCX);
		RAX += RCX;
		RAX += R15;
		return RAX;
	}
	case 12:
	{
		RSI = globals::base + 0x6AC;
		R9 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RAX -= RDI;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RSP = 0xDCBB02268230C67;
		RCX *= RSP;
		RAX *= RCX;
		RCX = RDI + RDI;
		RCX -= globals::base;
		RCX += 0xFFFFFFFFFFFF5629;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x12;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x24;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xD;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1A;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x34;
		RAX ^= RCX;
		RAX += RDI;
		return RAX;
	}
	case 13:
	{
		RSI = globals::base + 0x6AC;
		R15 = globals::base + 0x22DB7F31;
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RDX = RAX;
		RDX >>= 0x21;
		RDX ^= RAX;
		RAX = RDI;
		RAX = (~RAX);
		RAX *= R15;
		RAX += RDX;
		RAX += RDI;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RAX *= RCX;
		RCX = 0x8DDCF2B3E1571114;
		RAX ^= RCX;
		RCX = globals::base;
		RAX -= RCX;
		RCX = 0x6010B0A9C3D8407D;
		RAX ^= RCX;
		RCX = 0x4B13677AC2BC8B55;
		RAX *= RCX;
		return RAX;
	}
	case 14:
	{
		RSI = globals::base + 0x6AC;
		RBX = globals::base + 0x7B82;
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RCX = RAX;
		RCX >>= 0xD;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1A;
		RAX ^= RCX;
		// mov rdx,[rbp+0E8h]
		RDX -= RSI;
		RDX = 0; // Special case
		RDX = _rotl64(RDX, 0x10);
		RCX = RAX;
		RDX ^= R10;
		RCX >>= 0x34;
		RCX ^= RAX;
		RAX = globals::base;
		RDX = _byteswap_uint64(RDX);
		RCX ^= RAX;
		RAX = driver::read<uintptr_t>(RDX + 0x11);
		RAX *= RCX;
		RCX = 0x294BF04F8056DBA0;
		RAX += RCX;
		RCX = RDI;
		RCX ^= RBX;
		RAX -= RCX;
		RAX += RDI;
		RCX = globals::base + 0x22D3C70A;
		RAX += RCX;
		RCX = 0xF4E5078B5230FB51;
		RAX *= RCX;
		RCX = 0x5B401C942FFFFB4D;
		RAX += RCX;
		return RAX;
	}
	case 15:
	{
		R10 = driver::read<uintptr_t>(globals::base + 0x68FE117);
		RSI = globals::base + 0x6AC;
		RAX -= RDI;
		RCX = 0x867F13D085A61055;
		RAX *= RCX;
		// mov rcx,[rbp+0E8h]
		RCX -= RSI;
		RCX = 0; // Special case
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RCX = driver::read<uintptr_t>(RCX + 0x11);
		RSP = 0x341894F65D84D9E7;
		RCX *= RSP;
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x1A;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x34;
		RAX ^= RCX;
		RCX = globals::base;
		RAX -= RCX;
		RCX = 0x5AB80474995D546;
		RAX += RCX;
		RAX += RDI;
		RCX = globals::base;
		RAX += RCX;
		return RAX;
	}
	default:
		return 0;
	}
}