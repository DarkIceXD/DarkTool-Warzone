#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

		RBX = readMemory<uint64_t>(imageBase + 0x1796D488);
		if (RBX == 0) {
			return 0;
		}
		RAX -= 0x32;
		// movzx eax,al
		RDX = peb; // mov rdx,gs:[rax]
		RAX = imageBase + 0x7923;
		RAX -= RDX;
		RBX += RAX;
		RAX = RBX;
		RAX >>= 0x27;
		RCX = 0x0;
		RAX ^= RBX;
		RCX = _rotl64(RCX, 0x10);
		RCX ^= readMemory<uint64_t>(imageBase + 0x73FD0ED);
		RAX += RDX;
		RDX = imageBase + 0x24342779;
		RAX += RDX;
		RDX = 0x53465D65480AAB37;
		RAX ^= RDX;
		RCX = _byteswap_uint64(RCX);
		RBX = readMemory<uint64_t>(RCX + 0x11);
		RBX *= RAX;
		RAX = 0x1ECF2F482F4909CB;
		RBX *= RAX;
		return RBX;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RAX = readMemory<uint64_t>(clientInfo + 0x9ED78);
		RBX = peb; // mov rbx,gs:[rcx]
		RBX = ~RBX;
		// test rax,rax
		// je 00007FF7CE6902CEh
		RCX = RBX;
		RCX >>= 0x13;
		RCX &= 0xF;
		// cmp rcx,0Eh
		// ja 00007FF7CE68FD05h
		switch (RCX) {
		case 0: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = RBX * 0xFE;
			RCX -= R11;
			RCX += 0xFFFFFFFFFFFF115C;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x1F;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3E;
			RAX ^= RCX;
			RCX = 0x47B6839F6B6A7FAE;
			RAX ^= RCX;
			RCX = 0x64A06F3CFE35EE19;
			RAX -= RCX;
			RCX = 0x51ECB652967846CF;
			RAX *= RCX;
			RAX -= R11;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			return RAX;
		}
		case 1: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			R11 = imageBase;
			RCX = 0xD0C148D32DEA1CAB;
			RAX *= RCX;
			RCX = 0xDFA66850B39A8E27;
			RAX -= R11;
			RAX ^= RCX;
			RCX = 0x3A7984C27F5B3F2F;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x1B;
			RAX ^= RCX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RCX = RAX;
			RCX >>= 0x36;
			RCX ^= RAX;
			RDX = _byteswap_uint64(RDX);
			RAX = readMemory<uint64_t>(RDX + 0x5);
			RAX *= RCX;
			return RAX;
		}
		case 2: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			R11 = imageBase;
			R15 = imageBase + 0x594F91DD;
			RDX = RBX;
			RDX = ~RDX;
			RCX = R15;
			RCX = ~RCX;
			RDX *= RCX;
			RAX ^= RDX;
			RDX = imageBase + 0x684D79E4;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = R11 + 0x0F49E;
			RCX += RBX;
			RAX += RCX;
			RCX = 0xF0373F0197CA4E9B;
			RAX *= RCX;
			RCX = 0x8CE081E63E1B082B;
			RAX *= RCX;
			R14 = 0x456011E9A459DC07;
			RCX = RBX;
			RCX *= RDX;
			RCX += R14;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			return RAX;
		}
		case 3: {
			R14 = imageBase + 0xDA4C;
			R15 = imageBase + 0x3BE39329;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = RAX;
			RCX >>= 0xD;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1A;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x34;
			RAX ^= RCX;
			RCX = 0xA6B2AEE439A33015;
			RAX *= RCX;
			RCX = R14;
			RCX = ~RCX;
			RCX ^= RBX;
			RAX -= RCX;
			RDX = RAX;
			RDX >>= 0x20;
			RDX ^= RAX;
			RAX = R15;
			RAX = ~RAX;
			RAX ^= RBX;
			RAX += RDX;
			RDX = 0x0;
			RCX = 0xF70B9DEE3DA76EC4;
			RCX ^= RAX;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RAX = 0x1302CB88C0A51F36;
			RCX -= RAX;
			RDX = _byteswap_uint64(RDX);
			RAX = readMemory<uint64_t>(RDX + 0x5);
			RAX *= RCX;
			return RAX;
		}
		case 4: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			R11 = imageBase;
			R15 = imageBase + 0x4F38D955;
			RAX ^= R11;
			RDX = RBX;
			RDX *= R15;
			RCX = 0x36E45BE18E599A23;
			RCX -= RDX;
			RAX += RCX;
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
			RCX = 0xC08DC34CECBD95E3;
			RAX *= RCX;
			RAX -= R11;
			RAX += 0xFFFFFFFFFFFF6605;
			RAX += RBX;
			RCX = RAX;
			RCX >>= 0x15;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2A;
			RCX ^= RAX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RDX = _byteswap_uint64(RDX);
			RAX = readMemory<uint64_t>(RDX + 0x5);
			RAX *= RCX;
			return RAX;
		}
		case 5: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RAX -= RBX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RAX -= R11;
			RCX = 0xC3D3E8E44EBC4FB5;
			RAX *= RCX;
			RCX = 0x4DECB3DC6E98D321;
			RAX -= RCX;
			RAX ^= RBX;
			RCX = imageBase + 0x6037380D;
			RAX ^= RCX;
			RCX = 0xC249785EF00DD8F4;
			RAX ^= RCX;
			return RAX;
		}
		case 6: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			R11 = imageBase;
			RCX = 0x54218D701025DEBA;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1D;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3A;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1E;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3C;
			RAX ^= RCX;
			RCX = 0x9F91FF6CB637A7E2;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			RDX = readMemory<uint64_t>(RCX + 0x5);
			RCX = 0xB2B95D6F3DD2A1F;
			RDX *= RAX;
			RDX ^= R11;
			RAX = RDX;
			RAX >>= 0x27;
			RAX ^= RDX;
			RAX *= RCX;
			return RAX;
		}
		case 7: {
			RDX = imageBase + 0x6549;
			R11 = imageBase;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = imageBase + 0x6A392F04;
			RCX = ~RCX;
			RCX ^= RBX;
			RAX ^= RCX;
			RAX -= R11;
			RCX = 0xD1CF3F4C589239A9;
			RAX *= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = 0xA4D65267E2F8AAE9;
			RAX ^= RCX;
			RCX = RBX;
			RCX *= RDX;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1B;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x36;
			RAX ^= RCX;
			RCX = 0x279F0A313FFA90CA;
			RAX += RCX;
			return RAX;
		}
		case 8: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = 0xFFFFFFFFFFFF6FB4;
			RCX -= RBX;
			RCX -= R11;
			RAX += RCX;
			RCX = 0xCB9BB863A88D9370;
			RAX ^= RCX;
			RCX = 0xDE2A03113886668D;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x15;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2A;
			RAX ^= RCX;
			RAX -= RBX;
			RCX = R11 + 0x0D14D;
			RCX += RBX;
			RAX ^= RCX;
			RAX += R11;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			return RAX;
		}
		case 9: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = RAX;
			RCX >>= 0xD;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1A;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x34;
			RAX ^= RCX;
			RCX = 0x4105CE8A513F9037;
			RAX *= RCX;
			RAX ^= RBX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = 0xFFFFFFFFFFFF3F28;
			RCX -= RBX;
			RCX -= R11;
			RAX += RCX;
			RCX = 0xDD0134A9A3907D45;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x21;
			RAX ^= RCX;
			return RAX;
		}
		case 10: {
			R11 = imageBase;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = 0x5A277BDF2E8702;
			RAX -= RCX;
			RCX = 0x8631ECE0D7C79F0D;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x22;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x16;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2C;
			RAX ^= RCX;
			RAX ^= RBX;
			RCX = 0x16E96A3C1D655E49;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RCX = readMemory<uint64_t>(RCX + 0x5);
			RAX *= RCX;
			RAX -= R11;
			return RAX;
		}
		case 11: {
			uint64_t RBP_NEG_0x68 = imageBase;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = imageBase + 0x33E36D2B;
			RBP_NEG_0x68 = RCX; // mov [rbp-68h],rcx
			R11 = imageBase;
			RAX ^= R11;
			RCX = RAX;
			RCX >>= 0x1B;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x36;
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
			RCX = RBX;
			RCX = ~RCX;
			RCX *= RBP_NEG_0x68; // imul rcx,[rbp-68h]
			RAX += RCX;
			RCX = 0x20187069F8AC8D5B;
			RAX *= RCX;
			RCX = 0x56D78F8C4D23F74F;
			RCX *= RAX;
			RDX = 0x0;
			RAX = 0xB3D8B9347853E3D3;
			RDX = _rotl64(RDX, 0x10);
			RCX ^= RAX;
			RDX ^= R10;
			RDX = _byteswap_uint64(RDX);
			RAX = readMemory<uint64_t>(RDX + 0x5);
			RAX *= RCX;
			return RAX;
		}
		case 12: {
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = RAX;
			RCX >>= 0xB;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x16;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2C;
			RAX ^= RCX;
			RAX += RBX;
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
			RCX = RAX;
			RCX >>= 0x1E;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3C;
			RAX ^= RCX;
			RCX = 0x36FA328830743123;
			RAX += RCX;
			RCX = 0x6BFC4467FF5CD6DA;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = 0xA2AC7C71A3A8E763;
			RAX *= RCX;
			return RAX;
		}
		case 13: {
			uint64_t RBP_NEG_0x78 = imageBase;
			uint64_t RSP_0x78 = imageBase;
			RCX = imageBase + 0x2DCE72A2;
			RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
			RCX = imageBase + 0x7FFB070A;
			RSP_0x78 = RCX; // mov [rsp+78h],rcx
			R11 = imageBase;
			R15 = imageBase + 0x70E4CAEF;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = 0x5FB1A37AAFF921B7;
			RAX -= RCX;
			RCX = 0xE16397B6C5DE63AB;
			RAX *= RCX;
			RAX -= R11;
			RCX = R15;
			RCX = ~RCX;
			RCX += RBX;
			RAX ^= RCX;
			RCX = RBX;
			RCX ^= RSP_0x78; // xor rcx,[rsp+78h]
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = RAX;
			RCX >>= 0x28;
			RAX ^= RCX;
			RCX = RBX;
			RCX ^= RBP_NEG_0x78; // xor rcx,[rbp-78h]
			RAX += RCX;
			return RAX;
		}
		case 14: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RDX = 0x0;
			RCX = RBX;
			RCX = ~RCX;
			RDX = _rotl64(RDX, 0x10);
			RCX ^= RAX;
			RDX ^= R10;
			RDX = _byteswap_uint64(RDX);
			RAX = imageBase + 0x5DD2356A;
			RCX ^= RAX;
			RAX = readMemory<uint64_t>(RDX + 0x5);
			RAX *= RCX;
			RAX += RBX;
			RCX = RAX;
			RCX >>= 0x11;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x22;
			RAX ^= RCX;
			RCX = 0x9CAE8B89328D402;
			RAX ^= RCX;
			RCX = 0x44AE3455D34788A0;
			RAX += RCX;
			RCX = 0xE81B086404C44169;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0xD;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x1A;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x34;
			RAX ^= RCX;
			return RAX;
		}
		case 15: {
			R14 = imageBase + 0xF44F;
			R11 = imageBase + 0x85E3;
			R9 = readMemory<uint64_t>(imageBase + 0x73FD13F);
			RCX = 0xF8CC421C073B5A77;
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
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = _byteswap_uint64(RCX);
			RAX *= readMemory<uint64_t>(RCX + 0x5);
			RCX = R14;
			RCX = ~RCX;
			RCX *= RBX;
			RCX ^= RBX;
			RAX ^= RCX;
			RCX = 0x89DCE8409197261F;
			RAX *= RCX;
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
			RCX = RBX;
			RCX ^= R11;
			RAX += RCX;
			return RAX;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		R8 = readMemory<uint64_t>(imageBase + 0x15C56508);
		if (R8 == 0) {
			return 0;
		}
		RBX = peb; // mov rbx,gs:[rax]
		RBX = ~RBX;
		// test r8,r8
		// je 00007FF7CE7F628Ah
		RAX = RBX;
		RAX <<= 0x1B;
		RAX = _byteswap_uint64(RAX);
		RAX &= 0xF;
		// cmp rax,0Eh
		// ja 00007FF7CE7F5DAEh
		switch (RAX) {
		case 0: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			R14 = imageBase + 0x4322E738;
			R8 -= RBX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = R8;
			RAX >>= 0x21;
			RCX ^= R10;
			RAX ^= R8;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			RAX = RBX;
			RAX = ~RAX;
			RAX *= R14;
			R8 ^= RAX;
			RCX = RBX;
			RAX = imageBase;
			RCX -= RAX;
			RAX = R8;
			R8 = 0x8EB919DD092C3CD;
			RAX *= R8;
			R8 = RCX - 0x55868995;
			R8 ^= RAX;
			RAX = 0xF980E75CE4161693;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x17;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2E;
			R8 ^= RAX;
			return R8;
		}
		case 1: {
			R14 = imageBase + 0x736B6901;
			RCX = imageBase + 0x2F253BA2;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			R11 = 0x958980B6B63B2495;
			RAX = R14;
			RAX = ~RAX;
			RAX ^= RBX;
			RAX += R11;
			R8 += RAX;
			RAX = RBX;
			RAX *= RCX;
			R8 += RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = 0x15C1F09E3EE412FD;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x9;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x12;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x24;
			R8 ^= RAX;
			RCX = 0x0;
			RAX = RBX;
			RCX = _rotl64(RCX, 0x10);
			RAX ^= R8;
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			return R8;
		}
		case 2: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			RAX = readMemory<uint64_t>(RAX + 0xB);
			R8 *= RAX;
			RAX = 0x78ECBB60ACA05902;
			R8 ^= RAX;
			RAX = 0x22EAD42FB9F20D1B;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x8;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x10;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RAX = 0x2F9F872E4758DB3F;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RAX = imageBase;
			R8 -= RAX;
			R8 -= RBX;
			return R8;
		}
		case 3: {
			// push rbx
			// pushfq
			// pop rbx
			// popfq
			// pop rbx
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = 0x8B73190F87C67FC5;
			R8 *= RAX;
			RAX = 0xAFCD1235D805EE81;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0xD;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1A;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x34;
			R8 ^= RAX;
			RAX = 0x6299E4573BA81CDB;
			R8 ^= RAX;
			R8 ^= RBX;
			RAX = R8;
			RAX >>= 0x22;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			R8 *= readMemory<uint64_t>(RAX + 0xB);
			RAX = R8;
			RAX >>= 0x12;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x24;
			R8 ^= RAX;
			return R8;
		}
		case 4: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			R8 ^= RBX;
			RAX = R8;
			RAX >>= 0x21;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x17;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2E;
			R8 ^= RAX;
			RAX = 0xE6A90E7CC1DA845E;
			R8 ^= RAX;
			R8 -= RBX;
			RAX = 0x6E9C23E0CDE17E7D;
			R8 *= RAX;
			RAX = imageBase;
			RAX += R8;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			return R8;
		}
		case 5: {
			R14 = imageBase + 0x62E020D5;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = R8;
			RAX >>= 0x16;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2C;
			R8 ^= RAX;
			RAX = RBX;
			RAX *= R14;
			R8 -= RAX;
			RAX = 0x22262F30B7BB6069;
			R8 *= RAX;
			RCX = imageBase;
			RAX = RBX;
			RAX -= RCX;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x19;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x32;
			RCX = 0x0;
			RAX ^= R8;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			RAX = 0xCC488E14E6DE629B;
			R8 ^= RAX;
			return R8;
		}
		case 6: {
			uint64_t RSP_0x68 = imageBase;
			RDX = 0x98E624F5BCA6AE64;
			// pushfq
			// push rdx
			// pop rdx
			// pop rdx
			// popfq
			RAX = 0x7728BD0DB07B9423;
			RSP_0x68 = RAX; // mov [rsp+68h],rax
			R9 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = R8;
			RAX >>= 0x15;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2A;
			R8 ^= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0xE;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1C;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x38;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1B;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x36;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R9;
			RAX = _byteswap_uint64(RAX);
			RAX = readMemory<uint64_t>(RAX + 0xB);
			RAX *= RSP_0x68; // imul rax,[rsp+68h]
			R8 *= RAX;
			RAX = 0x9B6B8370C70E464D;
			R8 ^= RAX;
			RAX = 0x7A45D465799EAC85;
			R8 *= RAX;
			return R8;
		}
		case 7: {
			R11 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RDX = imageBase + 0x240E;
			RAX = RBX;
			RAX = ~RAX;
			RAX ^= RDX;
			R8 -= RAX;
			RAX = R8;
			RAX >>= 0x25;
			R8 ^= RAX;
			RAX = 0x1AD275B94943AA67;
			R8 *= RAX;
			R8 -= RBX;
			RAX = R8;
			RAX >>= 0x25;
			R8 ^= RAX;
			RAX = imageBase + 0x504F2DCE;
			R8 += RBX;
			R8 += RAX;
			RAX = 0x242F77F14F542704;
			RAX += R8;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R11;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			return R8;
		}
		case 8: {
			// pushfq
			// push rbx
			// pop rbx
			// pop rbx
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RCX = imageBase + 0x4ED02078;
			R14 = imageBase + 0xFCC3;
			RAX = 0x53DCDE662FF3AB67;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x28;
			R8 ^= RAX;
			RAX = R14;
			RAX = ~RAX;
			RAX ^= RBX;
			R8 ^= RAX;
			RAX = imageBase + 0xFBC0;
			RAX = ~RAX;
			RAX -= RBX;
			R8 += RAX;
			RAX = RBX + 1;
			RAX *= RCX;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0xA;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x14;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x28;
			R8 ^= RAX;
			R8 += RBX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			R8 *= readMemory<uint64_t>(RAX + 0xB);
			return R8;
		}
		case 9: {
			// push rbx
			// pushfq
			// pop rbx
			// popfq
			// pop rbx
			R14 = imageBase + 0x249D;
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			R8 += RBX;
			RAX = R8;
			RAX >>= 0x2;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x4;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x8;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x10;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RAX = R14;
			RAX = ~RAX;
			RAX += RBX;
			RAX ^= R8;
			R8 = 0x7046D6ABCA83A3A1;
			RCX = _byteswap_uint64(RCX);
			RAX += R8;
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			RAX = 0x45B553529B6ECB2B;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x6;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0xC;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x18;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x30;
			R8 ^= RAX;
			return R8;
		}
		case 10: {
			uint64_t RSP_0x78 = imageBase;
			RDX = 0x9C2A231980773FBA;
			// pushfq
			// push rdx
			// pop rdx
			// pop rdx
			// popfq
			RCX = imageBase + 0x793D7B70;
			RSP_0x78 = RCX; // mov [rsp+78h],rcx
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = 0xB4F5D91FEEBDBD67;
			R8 ^= RAX;
			RCX = imageBase + 0x6B80;
			RCX = ~RCX;
			RCX ^= RBX;
			RAX = RBX;
			RAX = ~RAX;
			RAX *= RSP_0x78; // imul rax,[rsp+78h]
			RAX -= RCX;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x21;
			R8 ^= RAX;
			RAX = 0x9BC71A2273F59459;
			R8 *= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			R8 *= readMemory<uint64_t>(RAX + 0xB);
			R8 += RBX;
			RAX = 0x4549C9206B801A23;
			R8 *= RAX;
			return R8;
		}
		case 11: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RCX = RBX;
			RCX = ~RCX;
			RAX = imageBase + 0xA432;
			RAX = ~RAX;
			RCX *= RAX;
			R8 ^= RCX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			R8 *= readMemory<uint64_t>(RAX + 0xB);
			RAX = imageBase;
			R8 -= RAX;
			R8 += 0xFFFFFFFFFFFFC4E9;
			R8 += RBX;
			RAX = imageBase;
			R8 -= RAX;
			RAX = 0x8F92F0752F9F1E65;
			R8 ^= RAX;
			RAX = 0x4C74D375E3A286F9;
			R8 *= RAX;
			RCX = imageBase + 0x2D70;
			RCX = ~RCX;
			RCX += RBX;
			RAX = R8;
			RAX >>= 0x25;
			RCX ^= RAX;
			R8 ^= RCX;
			return R8;
		}
		case 12: {
			RDX = imageBase + 0x5963E38F;
			R11 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			R8 += RBX;
			RAX = R8;
			R8 = 0x771094FCDC0B9A91;
			RCX = RBX;
			RAX *= R8;
			RCX = ~RCX;
			RCX *= RDX;
			R8 = RCX;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0xB;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x16;
			R8 ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = R8;
			RAX >>= 0x2C;
			RCX ^= R11;
			RAX ^= R8;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			RCX = RBX;
			RAX = imageBase + 0x42FE3DAC;
			RAX = ~RAX;
			RDX = imageBase + 0x1A47F740;
			RDX = ~RDX;
			RCX = ~RCX;
			RCX *= RAX;
			RDX -= RBX;
			RAX = 0x6ECEEE0DB4D0ACF8;
			R8 += RDX;
			R8 ^= RCX;
			R8 ^= RAX;
			return R8;
		}
		case 13: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RCX = imageBase + 0xB4EA;
			RAX = RCX;
			RAX = ~RAX;
			RAX += RBX;
			R8 += RAX;
			RAX = imageBase;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0xF;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1E;
			R8 ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RAX = R8;
			RAX >>= 0x3C;
			RAX ^= R8;
			RCX = _byteswap_uint64(RCX);
			R8 = readMemory<uint64_t>(RCX + 0xB);
			R8 *= RAX;
			R8 ^= RBX;
			RAX = 0xAE1E6A6337299648;
			R8 ^= RAX;
			RAX = 0x34CA4FE91ADAC4FD;
			R8 *= RAX;
			return R8;
		}
		case 14: {
			R10 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = imageBase;
			R8 -= RAX;
			R8 += 0xFFFFFFFFFFFFF598;
			R8 += RBX;
			RAX = imageBase + 0x120A4A7C;
			RAX = ~RAX;
			RAX ^= RBX;
			R8 ^= RAX;
			RAX = imageBase + 0xC86;
			RAX = ~RAX;
			RAX += RBX;
			R8 ^= RAX;
			RAX = 0x20461687593AEEC9;
			R8 *= RAX;
			RAX = imageBase + 0x96D;
			RAX = ~RAX;
			RAX += RBX;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0xE;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1C;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x38;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = _byteswap_uint64(RAX);
			R8 *= readMemory<uint64_t>(RAX + 0xB);
			RAX = R8;
			RAX >>= 0x1C;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x38;
			R8 ^= RAX;
			return R8;
		}
		case 15: {
			uint64_t RBP_NEG_0x38 = imageBase;
			uint64_t RBP_NEG_0x70 = imageBase;
			RAX = imageBase + 0x2B6E;
			RBP_NEG_0x70 = RAX; // mov [rbp-70h],rax
			R9 = readMemory<uint64_t>(imageBase + 0x73FD1E2);
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R9;
			RAX = _byteswap_uint64(RAX);
			RAX = readMemory<uint64_t>(RAX + 0xB);
			R8 *= RAX;
			RAX = imageBase;
			R8 -= RAX;
			RAX = 0x339AA31C76F6167B;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x10;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RAX = RBX;
			RAX = ~RAX;
			RAX -= RBP_NEG_0x38; // sub rax,[rbp-38h]
			RAX -= 0x28275D0D;
			R8 ^= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = RBX;
			RAX *= RBP_NEG_0x70; // imul rax,[rbp-70h]
			R8 += RAX;
			RAX = 0x908C8D6C87528AE0;
			R8 ^= RAX;
			return R8;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RBX = index;
		RCX = RBX * 0x13C8;
		RAX = 0x6D8C6D6A283FE64D;
		R11 = imageBase;
		RAX = _umul128(RAX, RCX, &RDX);
		RAX = RCX;
		R10 = 0xEE8E8444247587F7;
		RAX -= RDX;
		RAX >>= 0x1;
		RAX += RDX;
		RAX >>= 0xC;
		RAX = RAX * 0x1669;
		RCX -= RAX;
		RAX = 0x13FA39AB547994DB;
		R8 = RCX * 0x1669;
		RAX = _umul128(RAX, R8, &RDX);
		RDX >>= 0x9;
		RAX = RDX * 0x19A1;
		R8 -= RAX;
		RAX = 0x8888888888888889;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = 0x4F38F62DD4C9A845;
		RDX >>= 0x4;
		RCX = RDX * 0x1E;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = R8;
		RAX -= RDX;
		RAX >>= 0x1;
		RAX += RDX;
		RAX >>= 0x8;
		RCX += RAX;
		RAX = RCX * 0x30E;
		RCX = R8 * 0x310;
		RCX -= RAX;
		RAX = readMemory<uint16_t>(RCX + R11 + 0x7410830);
		R8 = RAX * 0x13C8;
		RAX = R10;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = R10;
		RDX >>= 0xD;
		RCX = RDX * 0x2257;
		R8 -= RCX;
		R9 = R8 * 0x3702;
		RAX = _umul128(RAX, R9, &RDX);
		RDX >>= 0xD;
		RAX = RDX * 0x2257;
		R9 -= RAX;
		RAX = 0x8618618618618619;
		RAX = _umul128(RAX, R9, &RDX);
		RAX = R9;
		RAX -= RDX;
		RAX >>= 0x1;
		RAX += RDX;
		RAX >>= 0x4;
		RCX = RAX * 0x15;
		RAX = 0x3159721ED7E75347;
		RAX = _umul128(RAX, R9, &RDX);
		RDX >>= 0x7;
		RCX += RDX;
		RAX = RCX * 0x530;
		RCX = R9 * 0x532;
		RCX -= RAX;
		R15 = readMemory<uint16_t>(RCX + R11 + 0x74163E0);
		return R15;
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
			return visible_list;
		}
	}
	return 0;
}