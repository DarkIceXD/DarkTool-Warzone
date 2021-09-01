#include "decryption.h"
#include "globals.h"
#include "offsets.h"
#include <stdlib.h>
#include "../driver/driver.h"
#define readMemory driver::read

extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
{
	uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

	RBX = readMemory<uint64_t>(imageBase + 0x17C272F8);
	if (RBX == 0) {
		return 0;
	}
	R8 = imageBase;
	RAX = RBX;
	RAX >>= 0x3;
	RDX = 0x966567ACD3D730C3;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0x6;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0xC;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0x18;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0x30;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0x1D;
	RBX ^= RAX;
	RAX = RBX;
	RAX >>= 0x3A;
	RCX = 0x0;
	RAX ^= RBX;
	RCX = _rotl64(RCX, 0x10);
	RCX ^= readMemory<uint64_t>(imageBase + 0x6AF90EB);
	RAX *= RDX;
	RCX = _byteswap_uint64(RCX);
	RAX ^= R8;
	RBX = readMemory<uint64_t>(RCX + 0xF);
	RBX *= RAX;
	return RBX;
}

extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
{
	uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

	RAX = readMemory<uint64_t>(clientInfo + 0x9DC18);
	R11 = peb; // mov r11,gs:[rcx]
	R11 = ~R11;
	// test rax,rax
	// je 00007FF6A9F0BB7Ah
	RCX = R11;
	RCX <<= 0x22;
	RCX = _byteswap_uint64(RCX);
	RCX &= 0xF;
	// cmp rcx,0Eh
	// ja 00007FF6A9F0B683h
	switch (RCX) {
	case 0: {
		R14 = imageBase + 0xB455;
		R15 = imageBase + 0xA226;
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RAX -= R11;
		RCX = RAX;
		RCX >>= 0x27;
		RAX ^= RCX;
		RCX = 0x2D46608595EB807;
		RAX += RCX;
		RCX = 0x4C070E6797D984CF;
		RAX *= RCX;
		RCX = 0x3B19C981BEE6CB2E;
		RAX += RCX;
		RCX = R14;
		RCX = ~RCX;
		RCX -= R11;
		RAX ^= RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = R15;
		RCX = ~RCX;
		RCX -= R11;
		RAX += RCX;
		return RAX;
	}
	case 1: {
		uint64_t RSP_0x60 = imageBase;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = imageBase + 0x791D9702;
		RSP_0x60 = RCX; // mov [rsp+60h],rcx
		R14 = imageBase + 0x9ADA;
		RCX = R11;
		RCX = ~RCX;
		RCX += RSP_0x60; // add rcx,[rsp+60h]
		RAX ^= RCX;
		RCX = R11 + 1;
		RCX *= R14;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x1B;
		RAX ^= RCX;
		RCX = RAX;
		RDX = 0x0;
		RCX >>= 0x36;
		RCX ^= RAX;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = readMemory<uint64_t>(RDX + 0x7);
		RAX *= RCX;
		RCX = imageBase;
		RCX += 0x4F35A830;
		RCX += R11;
		RAX ^= RCX;
		RCX = 0xC54E1DE273EBA3BF;
		RAX *= RCX;
		RCX = 0x95534A90119DE199;
		RAX *= RCX;
		RCX = 0x604CEB28B5C3299B;
		RAX -= RCX;
		return RAX;
	}
	case 2: {
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RDX = R11;
		RCX = RAX;
		RCX >>= 0x17;
		RAX ^= RCX;
		RCX = imageBase;
		RDX -= RCX;
		RCX = RAX;
		RDX -= 0x7D22AE7D;
		RCX >>= 0x2E;
		RDX ^= RCX;
		RAX ^= RDX;
		RCX = RAX;
		RCX >>= 0xF;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x1E;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x3C;
		RAX ^= RCX;
		RCX = 0xA98CBB46D81EEA24;
		RAX ^= RCX;
		RCX = 0x8DB07167CA6C7861;
		RAX *= RCX;
		RCX = 0x4C51D7E5334651C5;
		RAX *= RCX;
		RCX = imageBase;
		RAX -= RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		return RAX;
	}
	case 3: {
		uint64_t RBP_NEG_0x78 = imageBase;
		R14 = imageBase + 0x663F;
		RCX = 0xD633321105F5B017;
		RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RAX *= RBP_NEG_0x78; // imul rax,[rbp-78h]
		RCX = imageBase;
		RCX += 0x3352F216;
		RCX += R11;
		RCX ^= RAX;
		RAX = RCX;
		RAX >>= 0x27;
		RAX ^= RCX;
		RCX = 0x7FE12902D9C0515F;
		RAX -= RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = readMemory<uint64_t>(RCX + 0x7);
		RAX *= RCX;
		RAX ^= R11;
		RCX = 0xF111DD432B91B63F;
		RAX *= RCX;
		RCX = R11;
		RCX = ~RCX;
		RAX ^= RCX;
		RAX ^= R14;
		return RAX;
	}
	case 4: {
		RSI = imageBase + 0x7A4548DD;
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = RAX;
		RCX >>= 0x1A;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x34;
		RAX ^= RCX;
		RCX = R11;
		RCX *= RSI;
		RAX += RCX;
		RCX = 0x9143D5431B765517;
		RAX ^= RCX;
		RAX -= R11;
		RCX = RAX;
		RCX >>= 0x20;
		RAX ^= RCX;
		RCX = 0xFD7537AFDB0D7367;
		RAX *= RCX;
		return RAX;
	}
	case 5: {
		R14 = imageBase + 0xAE4E;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
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
		RCX = imageBase + 0xC203;
		RCX -= R11;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x16;
		RAX ^= RCX;
		RCX = RAX;
		RDX = R11;
		RCX >>= 0x2C;
		RDX = ~RDX;
		RDX += R14;
		RDX ^= RCX;
		RAX ^= RDX;
		RCX = 0x9AB7C77A83348731;
		RAX *= RCX;
		RAX ^= R11;
		RCX = R11 + RAX;
		RDX = 0x0;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = readMemory<uint64_t>(RDX + 0x7);
		RAX *= RCX;
		return RAX;
	}
	case 6: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = 0x2C79AC6B233152EF;
		RAX *= RCX;
		RCX = 0x212BD00FC7047561;
		RAX += RCX;
		RCX = imageBase;
		RAX ^= RCX;
		RCX = imageBase + 0x24D;
		RCX -= R11;
		RAX += RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = imageBase;
		RAX -= RCX;
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
		RAX += R11;
		return RAX;
	}
	case 7: {
		R14 = imageBase + 0x688D6654;
		R15 = imageBase + 0x1847758A;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = R15;
		RCX -= R11;
		RAX ^= RCX;
		RCX = 0x92173F0F74385389;
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x18;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x30;
		RAX ^= RCX;
		RCX = imageBase;
		RCX += 0x1ABCF14E;
		RCX += R11;
		RAX += RCX;
		RCX = 0x38E6778FAE77826D;
		RAX += RCX;
		RCX = R14;
		RCX = ~RCX;
		RCX += RAX;
		RAX = R11 + 1;
		RAX += RCX;
		RCX = RAX;
		RAX = 0xE5DF826AA0EE4847;
		RCX ^= RAX;
		RDX = 0x0;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RAX = readMemory<uint64_t>(RDX + 0x7);
		RAX *= RCX;
		return RAX;
	}
	case 8: {
		R14 = imageBase + 0x1707E983;
		R15 = imageBase + 0xF752;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RDX = 0x0;
		RCX = R11;
		RCX *= R14;
		RDX = _rotl64(RDX, 0x10);
		RAX -= RCX;
		RDX ^= R10;
		RDX = _byteswap_uint64(RDX);
		RCX = 0x47183DC31C96B766;
		RAX ^= RCX;
		RCX = R15;
		RCX = ~RCX;
		RDX = readMemory<uint64_t>(RDX + 0x7);
		RDX *= RAX;
		RAX = RDX;
		RAX >>= 0x16;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0x2C;
		RAX ^= RCX;
		RCX = 0x1541D86725F32FDB;
		RAX ^= R11;
		RAX ^= RDX;
		RAX *= RCX;
		RCX = R11;
		RCX = ~RCX;
		RAX += RCX;
		RCX = imageBase;
		RAX -= RCX;
		RAX -= 0x2A436179;
		RCX = 0xFDFBEB8FB40E05E7;
		RAX ^= RCX;
		return RAX;
	}
	case 9: {
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		R15 = imageBase + 0x42A071B5;
		RCX = imageBase;
		RAX -= RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = imageBase + 0x5D0215ED;
		RCX -= R11;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xB;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x16;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x2C;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x23;
		RAX ^= RCX;
		RCX = R11 + 1;
		RCX *= R15;
		RCX -= R11;
		RAX += RCX;
		RCX = 0xBBD3D80E07DCF4EF;
		RAX *= RCX;
		return RAX;
	}
	case 10: {
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		R14 = imageBase + 0x59204024;
		RCX = imageBase;
		RAX -= RCX;
		RAX += 0xFFFFFFFFFFFF0078;
		RAX += R11;
		RCX = imageBase + 0x95FC;
		RCX -= R11;
		RAX += RCX;
		RCX = 0x2D444ADE1A242D25;
		RAX *= RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = RAX;
		RCX >>= 0x13;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x26;
		RAX ^= RCX;
		RCX = R11;
		RCX ^= R14;
		RAX -= RCX;
		RCX = 0xB8A2F38A88039109;
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x26;
		RAX ^= RCX;
		return RAX;
	}
	case 11: {
		R15 = imageBase + 0x39485728;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = imageBase;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x23;
		RAX ^= RCX;
		RDX = 0x0;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RCX = imageBase + 0x1237CEEE;
		RDX = _byteswap_uint64(RDX);
		RDX = readMemory<uint64_t>(RDX + 0x7);
		RDX *= RAX;
		RAX = R11;
		RAX = ~RAX;
		RAX += RDX;
		RAX += RCX;
		RCX = 0xD9B4BAA24A9CCCDD;
		RAX *= RCX;
		RCX = 0xD9CED9A899EBC662;
		RAX ^= RCX;
		RCX = R11;
		RCX *= R15;
		RAX += RCX;
		return RAX;
	}
	case 12: {
		uint64_t RBP_NEG_0x68 = imageBase;
		R14 = imageBase + 0x37880550;
		RCX = 0x27DD6B3340C3BD5;
		RBP_NEG_0x68 = RCX; // mov [rbp-68h],rcx
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = imageBase;
		RAX ^= RCX;
		RCX = 0xDF3B4120AD5BC1CD;
		RAX *= RCX;
		RCX = R11;
		RCX = ~RCX;
		RAX ^= RCX;
		RAX ^= R14;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RCX = readMemory<uint64_t>(RCX + 0x7);
		RCX *= RBP_NEG_0x68; // imul rcx,[rbp-68h]
		RAX *= RCX;
		RCX = RAX;
		RCX >>= 0x5;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xA;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x14;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x28;
		RAX ^= RCX;
		RCX = imageBase;
		RAX -= RCX;
		RCX = 0xD50C771BE31E7C2F;
		RAX += RCX;
		RAX += R11;
		return RAX;
	}
	case 13: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RCX = 0x86DAC227CC627825;
		RAX *= RCX;
		RCX = imageBase;
		RAX += RCX;
		RAX ^= R11;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = RAX;
		RCX >>= 0x5;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0xA;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x14;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x28;
		RAX ^= RCX;
		RCX = 0x96D311F82D60B2F1;
		RAX *= RCX;
		RCX = imageBase;
		RAX += RCX;
		RCX = RAX;
		RCX >>= 0x1F;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x3E;
		RAX ^= RCX;
		return RAX;
	}
	case 14: {
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		R14 = imageBase + 0xEF5E;
		RCX = RAX;
		RCX >>= 0x22;
		RAX ^= RCX;
		RCX = imageBase;
		RCX += 0x6E2737EC;
		RCX += R11;
		RAX += RCX;
		RCX = R11;
		RCX ^= R14;
		RAX += RCX;
		RCX = 0x411E8EBFEF2DF1FF;
		RAX *= RCX;
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
		RDX = 0x0;
		RCX >>= 0x30;
		RCX ^= RAX;
		RDX = _rotl64(RDX, 0x10);
		RDX ^= R10;
		RAX = 0x69B6E601C5F5B3E;
		RCX ^= RAX;
		RDX = _byteswap_uint64(RDX);
		RAX = readMemory<uint64_t>(RDX + 0x7);
		RAX *= RCX;
		return RAX;
	}
	case 15: {
		uint64_t RBP_NEG_0x60 = imageBase;
		R10 = readMemory<uint64_t>(imageBase + 0x6AF9121);
		RAX -= R11;
		RCX = R11;
		RCX -= RBP_NEG_0x60; // sub rcx,[rbp-60h]
		RAX += RCX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RAX *= readMemory<uint64_t>(RCX + 0x7);
		RCX = 0x6586EBC94506E555;
		RAX *= RCX;
		RCX = imageBase;
		RAX -= RCX;
		RCX = RAX;
		RCX >>= 0x10;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x20;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x13;
		RAX ^= RCX;
		RCX = RAX;
		RCX >>= 0x26;
		RAX ^= RCX;
		return RAX;
	}
	}
}

extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
{
	uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

	RDI = readMemory<uint64_t>(imageBase + 0x15F16C98);
	if (RDI == 0) {
		return 0;
	}
	R10 = peb; // mov r10,gs:[rax]
	// test rdi,rdi
	// je 00007FF6AA0723BBh
	RAX = R10;
	RAX >>= 0x15;
	RAX &= 0xF;
	// cmp rax,0Eh
	// ja 00007FF6AA071E8Eh
	switch (RAX) {
	case 0: {
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = RDI;
		RAX >>= 0x19;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x32;
		RDI ^= RAX;
		RAX = 0xB5EDA6AE56A4C823;
		RDI *= RAX;
		RDI += R10;
		RAX = RDI;
		RAX >>= 0x4;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x8;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x10;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x20;
		RDI ^= RAX;
		RAX = 0xBC79F7EA33328282;
		RDI ^= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RAX = RDI;
		RAX >>= 0x3;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x6;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xC;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RDI ^= RAX;
		RAX = 0x2B606A7FE328D223;
		RDI -= RAX;
		return RDI;
	}
	case 1: {
		R15 = imageBase + 0xD2FB;
		R11 = imageBase;
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RDI ^= R10;
		RDI ^= R15;
		RDI ^= R11;
		RAX = RDI;
		RAX >>= 0x20;
		RCX = 0x0;
		RAX ^= RDI;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RCX = _byteswap_uint64(RCX);
		RDI = readMemory<uint64_t>(RCX + 0xB);
		RDI *= RAX;
		RAX = 0x46E1A0BAB0988A98;
		RDI -= RAX;
		RAX = RDI;
		RAX >>= 0x5;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xA;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x14;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x28;
		RDI ^= RAX;
		RAX = 0x3103C276BE7CCF71;
		RDI *= RAX;
		return RDI;
	}
	case 2: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		R11 = imageBase;
		R13 = imageBase + 0x2CE4;
		R12 = imageBase + 0x2C28B2BB;
		RCX = R10;
		RCX = ~RCX;
		RAX = R13;
		RAX = ~RAX;
		RDI += RAX;
		RDI += RCX;
		RAX = RDI;
		RAX >>= 0xD;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x1A;
		RDI ^= RAX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RAX = RDI;
		RAX >>= 0x34;
		RCX ^= R9;
		RAX ^= RDI;
		RCX = _byteswap_uint64(RCX);
		RDI = readMemory<uint64_t>(RCX + 0xB);
		RDI *= RAX;
		RDI += R11;
		RCX = R10;
		RCX *= R12;
		RDI += RCX;
		RAX = 0xCAD9C1208CBAEF4B;
		RDI *= RAX;
		RAX = 0x2AAED8C91B8C3519;
		RDI *= RAX;
		RDI += R10;
		return RDI;
	}
	case 3: {
		R11 = imageBase;
		R15 = imageBase + 0x18C4FEC5;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = RDI;
		RAX >>= 0x24;
		RDI ^= RAX;
		RDI ^= R11;
		RAX = RDI;
		RAX >>= 0x1F;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x3E;
		RDI ^= RAX;
		RAX = 0x273D1CFA301B1EEF;
		RDI *= RAX;
		RAX = 0x6A48C264051AC7E2;
		RDI ^= RAX;
		RAX = R10;
		RAX = ~RAX;
		RAX += R15;
		RDI ^= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RDI += R11;
		return RDI;
	}
	case 4: {
		R10 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		R11 = imageBase;
		RAX = RDI;
		RAX >>= 0x6;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xC;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RAX ^= RDI;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R10;
		RCX = _byteswap_uint64(RCX);
		RDX = readMemory<uint64_t>(RCX + 0xB);
		RDX *= RAX;
		RAX = RDX;
		RAX >>= 0xA;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0x14;
		RDX ^= RAX;
		RDI = RDX;
		RDI >>= 0x28;
		RDI ^= RDX;
		RDI ^= R11;
		RAX = 0xB5253389969C6067;
		RDI *= RAX;
		RAX = 0x30C1C84EEA97399F;
		RDI *= RAX;
		RDI ^= R11;
		RAX = 0x30DF8155532CE297;
		RDI += RAX;
		return RDI;
	}
	case 5: {
		R11 = imageBase;
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RAX = R11 + 0x2B8D8B93;
		RCX = _byteswap_uint64(RCX);
		RAX += R10;
		RAX ^= RDI;
		RDI = readMemory<uint64_t>(RCX + 0xB);
		RDI *= RAX;
		RAX = RDI;
		RAX >>= 0xD;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x1A;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x34;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RDI ^= RAX;
		RAX = 0xB100F3928730CB0F;
		RDI *= RAX;
		RAX = 0xC8FFE7FA4D6CAB90;
		RDI ^= RAX;
		RAX = imageBase + 0x46BDA39F;
		RAX = ~RAX;
		RAX *= R10;
		RDI += RAX;
		RAX = 0x11C1A378ED766D44;
		RDI ^= RAX;
		return RDI;
	}
	case 6: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		R11 = imageBase;
		R15 = imageBase + 0x6313;
		RAX = 0x22F851B78A6BB7DF;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x20;
		RDI ^= RAX;
		RAX = 0x43AF102F343234D7;
		RDI *= RAX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= R9;
		RAX = R15;
		RAX = ~RAX;
		RAX += R10;
		RAX += RDI;
		RCX = _byteswap_uint64(RCX);
		RDI = readMemory<uint64_t>(RCX + 0xB);
		RDI *= RAX;
		RAX = 0xA26FC39781CB8E5B;
		RDI *= RAX;
		RDI -= R11;
		RAX = RDI;
		RAX >>= 0x3;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x6;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xC;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RDI ^= RAX;
		return RDI;
	}
	case 7: {
		R11 = imageBase;
		R14 = imageBase + 0x6B136CF1;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = RDI;
		RAX >>= 0x1B;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x36;
		RDI ^= RAX;
		RDI += R11;
		RAX = 0xD91E239C7A255095;
		RDI *= RAX;
		RAX = R14;
		RAX = ~RAX;
		RAX ^= R10;
		RDI -= RAX;
		RAX = 0x317920DF87AE7EC7;
		RDI *= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RDI ^= RAX;
		RAX = 0x6B5E97084255ECC9;
		RDI += RAX;
		return RDI;
	}
	case 8: {
		R11 = imageBase;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = R10;
		RAX = ~RAX;
		RAX -= R11;
		RAX += 0xFFFFFFFFFFFF2DCE;
		RDI += RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RDI -= R11;
		RDI += R10;
		RAX = 0x76D55F303F89CFCB;
		RDI ^= RAX;
		RAX = 0xBAC3AEA922B9BF1F;
		RDI *= RAX;
		RAX = 0xAF94C03CBECE7649;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x15;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x2A;
		RDI ^= RAX;
		return RDI;
	}
	case 9: {
		R11 = imageBase;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = 0xFBD87AED437EFFC9;
		RDI ^= RAX;
		RAX = R11 + 0x0C295;
		RAX += R10;
		RDI ^= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RAX = R10;
		RAX = ~RAX;
		RAX -= R11;
		RAX += 0xFFFFFFFF9AEA3E8E;
		RDI += RAX;
		RAX = 0x674C9ABDD5189573;
		RDI *= RAX;
		RAX = RDI;
		RAX >>= 0x6;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xC;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x18;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x30;
		RDI ^= RAX;
		RDI -= R11;
		RAX = RDI;
		RAX >>= 0x28;
		RDI ^= RAX;
		return RDI;
	}
	case 10: {
		R15 = imageBase + 0xB2D;
		R14 = imageBase + 0x5F19;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RDI += R10;
		RAX = RDI;
		RAX >>= 0x27;
		RDI ^= RAX;
		RAX = R10;
		RAX *= R15;
		RDI ^= RAX;
		RAX = 0x6F5B0662FEE5B96D;
		RDI *= RAX;
		RAX = 0x427697E150BDABF4;
		RDI ^= RAX;
		RAX = R10;
		RAX *= R14;
		RDI += RAX;
		RAX = 0x663284DF805F0BD3;
		RDI *= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		return RDI;
	}
	case 11: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		R11 = imageBase;
		RAX = 0xCE51B5AE58D1B0A0;
		RAX -= R11;
		RDI += RAX;
		RAX = RDI;
		RAX >>= 0x2;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x4;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x8;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x10;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x20;
		RDI ^= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R9;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RDI ^= R11;
		RAX = RDI;
		RAX >>= 0x24;
		RDI ^= RAX;
		RAX = 0x9444AAA1C3FA7CAF;
		RDI *= RAX;
		return RDI;
	}
	case 12: {
		uint64_t RSP_0x78 = imageBase;
		// push rbx
		// pushfq
		// pop rbx
		// popfq
		// pop rbx
		R11 = imageBase;
		RAX = imageBase + 0xDE9B;
		RSP_0x78 = RAX; // mov [rsp+78h],rax
		RCX = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = 0x50F906BEB278F9B0;
		RDI -= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= RCX;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RDI += R11;
		RAX = RDI;
		RAX >>= 0x26;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x13;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x26;
		RDI ^= RAX;
		RAX = 0x699A5342AEDC9297;
		RDI *= RAX;
		RAX = 0xEF7CC55FD8736EA0;
		RDI ^= RAX;
		RAX = R10;
		RAX = ~RAX;
		RAX *= RSP_0x78; // imul rax,[rsp+78h]
		RDI += RAX;
		return RDI;
	}
	case 13: {
		R11 = imageBase;
		R15 = imageBase + 0xE14F;
		R8 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RDI -= R11;
		RDI -= R11;
		RAX = 0x2489621CAF27AE37;
		RDI *= RAX;
		RAX = 0x56D3C180B14A2BD4;
		RDI -= RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R8;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RAX = RDI;
		RAX >>= 0x25;
		RDI ^= RAX;
		RDI ^= R10;
		RDI ^= R15;
		RAX = R10;
		RAX -= R11;
		RAX += 0xFFFFFFFFDF6B4366;
		RDI += RAX;
		return RDI;
	}
	case 14: {
		R11 = imageBase;
		R12 = imageBase + 0xE980;
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = 0x5F3BDAB4FDE2662D;
		RDI *= RAX;
		RAX = 0x77CE7CC5626E4DBF;
		RDI += RAX;
		RAX = 0x36895F63430C9DF0;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0xA;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x14;
		RDI ^= RAX;
		RCX = 0x0;
		RCX = _rotl64(RCX, 0x10);
		RAX = RDI;
		RCX ^= R9;
		RAX >>= 0x28;
		RAX ^= RDI;
		RCX = _byteswap_uint64(RCX);
		RDI = readMemory<uint64_t>(RCX + 0xB);
		RDI *= RAX;
		RAX = R11 + 0x0BE4F;
		RAX += R10;
		RDI += RAX;
		RAX = R12;
		RAX = ~RAX;
		RAX ^= R10;
		RDI += RAX;
		RDI -= R10;
		return RDI;
	}
	case 15: {
		R9 = readMemory<uint64_t>(imageBase + 0x6AF91F5);
		RAX = 0x346A8990F8C2C81B;
		RDI *= RAX;
		RDI ^= R10;
		RAX = RDI;
		RAX >>= 0xB;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x16;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x2C;
		RDI ^= RAX;
		RAX = R10 * 0xFE;
		RDI += RAX;
		RAX = 0x0;
		RAX = _rotl64(RAX, 0x10);
		RAX ^= R9;
		RAX = _byteswap_uint64(RAX);
		RDI *= readMemory<uint64_t>(RAX + 0xB);
		RAX = RDI;
		RAX >>= 0xA;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x14;
		RDI ^= RAX;
		RAX = RDI;
		RAX >>= 0x28;
		RDI ^= RAX;
		RAX = 0x5AD148923DD99C5B;
		RDI += RAX;
		return RDI;
	}
	}
}

extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
{
	uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

	RBX = index;
	RCX = RBX * 0x13C8;
	RAX = 0x5A74536D75719C7;
	RBX = imageBase;
	RAX = _umul128(RAX, RCX, &RDX);
	RAX = RCX;
	R11 = 0xAAAAAAAAAAAAAAAB;
	RAX -= RDX;
	R10 = 0xF8CD4F6BC9B2304B;
	RAX >>= 0x1;
	RAX += RDX;
	RAX >>= 0xC;
	RAX = RAX * 0x1F4F;
	RCX -= RAX;
	RAX = 0xFF00FF00FF00FF01;
	R8 = RCX * 0x1F4F;
	RAX = _umul128(RAX, R8, &RDX);
	RDX >>= 0xD;
	RAX = RDX * 0x2020;
	R8 -= RAX;
	RAX = 0xA9F28E9039177BE5;
	RAX = _umul128(RAX, R8, &RDX);
	RAX = R11;
	RDX >>= 0xB;
	RCX = RDX * 0xC0D;
	RAX = _umul128(RAX, R8, &RDX);
	RDX >>= 0x1;
	RCX += RDX;
	RAX = RCX + RCX * 2;
	RAX += RAX;
	RCX = R8 * 8;
	RCX -= RAX;
	RAX = readMemory<uint16_t>(RCX + RBX + 0x6B04510);
	R8 = RAX * 0x13C8;
	RAX = R10;
	RAX = _umul128(RAX, R8, &RDX);
	RAX = R10;
	RDX >>= 0xD;
	RCX = RDX * 0x20ED;
	R8 -= RCX;
	R9 = R8 * 0x29C1;
	RAX = _umul128(RAX, R9, &RDX);
	RAX = R11;
	RDX >>= 0xD;
	RCX = RDX * 0x20ED;
	R9 -= RCX;
	RAX = _umul128(RAX, R9, &RDX);
	RAX = 0x135C81135C81135D;
	RDX >>= 0x6;
	RCX = RDX + RDX * 2;
	RAX = _umul128(RAX, R9, &RDX);
	RCX <<= 0x5;
	RAX = R9;
	RAX -= RDX;
	RAX >>= 0x1;
	RAX += RDX;
	RAX >>= 0x6;
	RCX += RAX;
	RAX = RCX * 0xEE;
	RCX = R9 * 0xF0;
	RCX -= RAX;
	RSI = readMemory<uint16_t>(RCX + RBX + 0x6B08D60);
	return RSI;
}

struct ref_def_key
{
	int ref0, ref1, ref2;
};

uintptr_t decryption::get_ref_def(const uint64_t imageBase, const uintptr_t ref_def_ptr)
{
	const auto crypt = driver::read<ref_def_key>(imageBase + ref_def_ptr);

	DWORD lower = crypt.ref0 ^ (crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr)) * ((crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr)) + 2);
	DWORD upper = crypt.ref1 ^ (crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr + 0x4)) * ((crypt.ref2 ^ (uint64_t)(imageBase + ref_def_ptr + 0x4)) + 2);

	return (uint64_t)upper << 32 | lower;
}