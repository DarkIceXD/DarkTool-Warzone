#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

		RBX = readMemory<uint64_t>(imageBase + 0x1803E988);
		if (RBX == 0) {
			return 0;
		}
		RAX = imageBase;
		RDX = RBX + RAX;
		RAX = 0xF7722301C0F805AF;
		RDX *= RAX;
		RAX = RDX;
		RAX >>= 0x5;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0xA;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0x14;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0x28;
		RDX ^= RAX;
		RAX = RDX;
		RAX >>= 0x12;
		RDX ^= RAX;
		RAX = RDX;
		RCX = 0x0;
		RAX >>= 0x24;
		RCX = _rotl64(RCX, 0x10);
		RAX ^= RDX;
		RCX ^= readMemory<uint64_t>(imageBase + 0x7420100);
		RCX = ~RCX;
		RBX = readMemory<uint64_t>(RCX + 0xB);
		RBX *= RAX;
		RAX = 0xF02663FD564FD7EB;
		RBX *= RAX;
		return RBX;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RAX = readMemory<uint64_t>(clientInfo + 0x9FDE8);
		RBX = peb; // mov rbx,gs:[rcx]
		RBX = ~RBX;
		// test rax,rax
		// je 00007FF7934DB86Eh
		RCX = RBX;
		RCX >>= 0x12;
		RCX &= 0xF;
		// cmp rcx,0Eh
		// ja 00007FF7934DB3A6h
		switch (RCX) {
		case 0: {
			R11 = readMemory<uint64_t>(imageBase + 0x742012B);
			RDX = imageBase + 0x44A7A7BD;
			RCX = RAX;
			RCX >>= 0x1F;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3E;
			RAX ^= RCX;
			RCX = RBX;
			RCX = ~RCX;
			RCX += RDX;
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
			RCX = imageBase;
			RAX ^= RCX;
			RDX = imageBase + 0x174468E4;
			R8 = 0x0;
			R8 = _rotl64(R8, 0x10);
			RCX = RAX;
			R8 ^= R11;
			RDX = ~RDX;
			RDX ^= RBX;
			R8 = ~R8;
			RCX -= RDX;
			RAX = readMemory<uint64_t>(R8 + 0xD);
			RAX *= RCX;
			RCX = 0x85247CBDA5162E69;
			RAX *= RCX;
			RCX = 0x5E84500527FE80EE;
			RAX += RCX;
			return RAX;
		}
		case 1: {
			R14 = imageBase + 0xB275;
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
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
			RCX >>= 0x11;
			RAX ^= RCX;
			RDX = RAX;
			RDX >>= 0x22;
			RDX ^= RAX;
			RAX = RBX;
			RCX = imageBase + 0x776FC6E9;
			RAX = ~RAX;
			RAX += RDX;
			RAX += RCX;
			RCX = RBX;
			RCX *= R14;
			RAX -= RCX;
			RCX = 0x5294B8E2B4503BD5;
			RAX ^= RCX;
			RDX = 0x0;
			RCX = RAX;
			RDX = _rotl64(RDX, 0x10);
			RDX ^= R10;
			RAX = 0x46AF1918BC28C49;
			RCX ^= RAX;
			RDX = ~RDX;
			RAX = readMemory<uint64_t>(RDX + 0xD);
			RAX *= RCX;
			RCX = 0xC04ECE04B97543B9;
			RAX *= RCX;
			return RAX;
		}
		case 2: {
			R15 = imageBase + 0x466367AE;
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = imageBase;
			RDX = RBX;
			RCX = RCX * 0xFE;
			RDX ^= R15;
			RCX -= RDX;
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = 0x24C22309981B21D;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x13;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x26;
			RAX ^= RCX;
			RCX = 0x3AECE62ADE788733;
			RAX *= RCX;
			RCX = 0x6003E2FCB3FA732E;
			RAX += RCX;
			return RAX;
		}
		case 3: {
			uint64_t RBP_NEG_0x80 = imageBase;
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			R15 = imageBase + 0x6167;
			RCX = imageBase + 0x269F;
			RBP_NEG_0x80 = RCX; // mov [rbp-80h],rcx
			RDX = imageBase + 0x685485D0;
			RCX = RBX;
			RCX *= RDX;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = 0xDD0C704114FE69B1;
			RAX *= RCX;
			RCX = 0xA958A2FC4193469E;
			RCX -= RBX;
			RAX += RCX;
			RCX = RBX;
			RCX *= R15;
			RAX -= RCX;
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
			RCX *= RBP_NEG_0x80; // imul rcx,[rbp-80h]
			RAX += RCX;
			return RAX;
		}
		case 4: {
			R14 = imageBase + 0x1CF07BBC;
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = imageBase;
			RAX -= RCX;
			RCX = 0xADC81E50588F17C9;
			RAX *= RCX;
			RCX = 0x5290A93DF73A2214;
			RAX ^= RCX;
			RCX = RBX;
			RCX = ~RCX;
			RCX *= R14;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = RAX;
			RCX >>= 0x9;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x12;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			RAX += RBX;
			RCX = 0xC8C2CB328E220AC9;
			RAX ^= RCX;
			return RAX;
		}
		case 5: {
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = RAX;
			RCX >>= 0x8;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = imageBase;
			RAX ^= RCX;
			RCX = 0x29B50F59172BD330;
			RAX ^= RCX;
			RCX = 0x561637634FE96C25;
			RAX *= RCX;
			RCX = imageBase;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x16;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x2C;
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
		case 6: {
			uint64_t RSP_0x50 = imageBase;
			RCX = 0x76C44C879E7C4119;
			RSP_0x50 = RCX; // mov [rsp+50h],rcx
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = RAX;
			RCX >>= 0x1A;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x34;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x26;
			RCX ^= RAX;
			RAX = 0xA174066EB8AE22D0;
			RCX ^= RAX;
			RAX = imageBase;
			RCX -= RAX;
			RAX = RBX - 0x3C2DA278;
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0xD);
			RCX *= RSP_0x50; // imul rcx,[rsp+50h]
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RAX -= RBX;
			return RAX;
		}
		case 7: {
			uint64_t RSP_0x48 = imageBase;
			RCX = 0xCA63CC0460D05F03;
			RSP_0x48 = RCX; // mov [rsp+48h],rcx
			R15 = imageBase + 0x1C92;
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			RDX = R15;
			RDX = ~RDX;
			RCX = 0xBA475E161600935;
			RDX ^= RBX;
			RCX -= RDX;
			RAX += RCX;
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
			RCX >>= 0xD;
			RAX ^= RCX;
			RCX = RAX;
			RDX = imageBase + 0x5062;
			RCX >>= 0x1A;
			RDX = ~RDX;
			RAX ^= RCX;
			RDX += RBX;
			RCX = RAX;
			RCX >>= 0x34;
			RDX ^= RCX;
			RAX ^= RDX;
			RCX = 0x2D5F072877E25500;
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0xD);
			RCX *= RSP_0x48; // imul rcx,[rsp+48h]
			RAX *= RCX;
			return RAX;
		}
		case 8: {
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = imageBase;
			RCX += 0x6AA30B3E;
			RCX += RBX;
			RAX ^= RCX;
			RCX = 0x95A5FE1D3FAAFAB;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RAX += RBX;
			RCX = RAX;
			RCX >>= 0x9;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x12;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			RCX = 0x53A4C6E054132C7D;
			RAX *= RCX;
			RCX = imageBase;
			RAX = RAX + RCX * 2;
			RAX -= RBX;
			RAX += 0x729D6B9B;
			return RAX;
		}
		case 9: {
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = imageBase;
			RAX -= RCX;
			RCX = RAX;
			RCX >>= 0x21;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0xD);
			RAX *= RCX;
			RAX -= RBX;
			RCX = imageBase;
			RAX -= RCX;
			RCX = 0xF2CDB9332D549107;
			RAX *= RCX;
			RCX = 0x8A3D0815B0D64F83;
			RAX *= RCX;
			RCX = 0x8B99D8B4A3996DEE;
			RAX ^= RCX;
			return RAX;
		}
		case 10: {
			uint64_t RBP_NEG_0x78 = imageBase;
			uint64_t RSP_0x48 = imageBase;
			RCX = imageBase + 0x3082;
			RSP_0x48 = RCX; // mov [rsp+48h],rcx
			RCX = 0x540AAB046719B811;
			RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = RBX;
			RCX = ~RCX;
			RCX *= RSP_0x48; // imul rcx,[rsp+48h]
			RAX += RCX;
			RAX += RBX;
			RCX = 0xDF4DAFD552784CE5;
			RCX -= RBX;
			RAX += RCX;
			RCX = 0x3F80DE5F719A5953;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x1D;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x3A;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0xD);
			RCX *= RBP_NEG_0x78; // imul rcx,[rbp-78h]
			RAX *= RCX;
			return RAX;
		}
		case 11: {
			R11 = imageBase + 0xEC3D;
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RAX += RBX;
			RCX = RBX + 1;
			RCX *= R11;
			RCX += RBX;
			RAX += RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = 0x564163D4144DA674;
			RAX += RCX;
			RCX = 0x7DF6C4B8AC4AA83B;
			RAX *= RCX;
			RCX = 0x5F9915E2A23897DC;
			RAX -= RCX;
			RCX = RAX;
			RCX >>= 0x10;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			return RAX;
		}
		case 12: {
			R9 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R9;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = RAX;
			RCX >>= 0x11;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x22;
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
			RCX = imageBase;
			RAX += RCX;
			RCX = RAX;
			RCX >>= 0x21;
			RAX ^= RCX;
			RCX = imageBase;
			RAX -= RCX;
			RAX += 0xFFFFFFFF9DB2C357;
			RAX += RBX;
			RCX = 0x9863F38C7BF440B7;
			RAX *= RCX;
			RCX = 0x14E0C67082A7D53F;
			RAX *= RCX;
			return RAX;
		}
		case 13: {
			R14 = imageBase + 0x7339;
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = RAX;
			RCX >>= 0x24;
			RAX ^= RCX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RAX *= readMemory<uint64_t>(RCX + 0xD);
			RCX = imageBase;
			RCX += 0x59CF17C4;
			RCX += RBX;
			RAX += RCX;
			RCX = 0x99F0869ACD587455;
			RAX ^= RCX;
			RCX = 0x9BD39BDBB5698FC7;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0xA;
			RAX ^= RCX;
			RCX = RAX;
			RCX >>= 0x14;
			RAX ^= RCX;
			RDX = RAX;
			RDX >>= 0x28;
			RDX ^= RAX;
			RAX = RBX;
			RAX = ~RAX;
			RAX += RDX;
			RAX += R14;
			return RAX;
		}
		case 14: {
			uint64_t RBP_NEG_0x78 = imageBase;
			R14 = imageBase + 0x649C;
			RCX = 0xC48ED9BEE4C4A129;
			R15 = imageBase + 0x54D54795;
			RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			RCX = readMemory<uint64_t>(RCX + 0xD);
			RCX *= RBP_NEG_0x78; // imul rcx,[rbp-78h]
			RAX *= RCX;
			RCX = RBX;
			RCX ^= R15;
			RAX += RCX;
			RAX ^= RBX;
			RAX -= RBX;
			RCX = 0x8B9FE6D1F0711D73;
			RAX *= RCX;
			RCX = RAX;
			RCX >>= 0x27;
			RAX ^= RCX;
			RCX = RBX;
			RCX = ~RCX;
			RCX *= R14;
			RAX ^= RCX;
			return RAX;
		}
		case 15: {
			R10 = readMemory<uint64_t>(imageBase + 0x742012B);
			R15 = imageBase + 0x6C4F;
			RCX = RAX;
			RCX >>= 0x20;
			RAX ^= RCX;
			RCX = 0xF2DE823B148DE081;
			RAX *= RCX;
			RCX = RBX;
			RCX ^= RAX;
			RDX = 0x0;
			RDX = _rotl64(RDX, 0x10);
			RCX ^= R15;
			RDX ^= R10;
			RDX = ~RDX;
			RAX = readMemory<uint64_t>(RDX + 0xD);
			RAX *= RCX;
			RCX = 0x50DC4E1E2C3449F;
			RAX *= RCX;
			RAX -= RBX;
			RAX ^= RBX;
			RCX = 0x7023B028DF1306AD;
			RAX *= RCX;
			return RAX;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		R8 = readMemory<uint64_t>(imageBase + 0x15E00828);
		if (R8 == 0) {
			return 0;
		}
		RBX = peb; // mov rbx,gs:[rax]
		// test r8,r8
		// je 00007FF793640CCEh
		RAX = RBX;
		RAX <<= 0x2B;
		RAX = _byteswap_uint64(RAX);
		RAX &= 0xF;
		// cmp rax,0Eh
		// ja 00007FF79364089Ah
		switch (RAX) {
		case 0: {
			R11 = imageBase + 0x1964A9EF;
			RCX = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = 0xE65E6BAF9C1CF9EE;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0xF;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x1E;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x3C;
			R8 ^= RAX;
			RAX = 0x544E72501F255A6B;
			R8 *= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = imageBase;
			R8 += RAX;
			RAX = 0x1629A73EA68D757B;
			R8 += RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= RCX;
			RAX = ~RAX;
			RAX = readMemory<uint64_t>(RAX + 0x19);
			RAX *= R8;
			R8 = R11;
			RAX += RBX;
			R8 = ~R8;
			R8 += RAX;
			return R8;
		}
		case 1: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = R8;
			RAX >>= 0x9;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x12;
			R8 ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = R8;
			RAX >>= 0x24;
			RCX ^= R10;
			RAX ^= R8;
			RCX = ~RCX;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			RCX = imageBase + 0x4A304FBB;
			R8 *= RAX;
			RAX = RBX;
			RAX = ~RAX;
			RAX += RCX;
			R8 ^= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = 0x5389C799EE48F8D0;
			R8 ^= RAX;
			RAX = 0x7AD8D1482BD2EF1D;
			R8 *= RAX;
			RAX = imageBase + 0x45FA1C03;
			R8 -= RBX;
			RAX = ~RAX;
			R8 += RAX;
			RAX = imageBase;
			R8 -= RAX;
			return R8;
		}
		case 2: {
			uint64_t RBP_NEG_0x38 = imageBase;
			uint64_t RSP_0x60 = imageBase;
			// push rbx
			// pushfq
			// pop rbx
			// popfq
			// pop rbx
			RAX = imageBase + 0x75DD805E;
			RBP_NEG_0x38 = RAX; // mov [rbp-38h],rax
			RAX = imageBase + 0x84BA;
			RSP_0x60 = RAX; // mov [rsp+60h],rax
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = RBX;
			RAX *= RBP_NEG_0x38; // imul rax,[rbp-38h]
			R8 += RAX;
			RAX = RBX;
			RAX *= RSP_0x60; // imul rax,[rsp+60h]
			R8 += RAX;
			RAX = RBX;
			RAX = ~RAX;
			R8 ^= RAX;
			RAX = imageBase + 0x4063;
			R8 ^= RAX;
			RCX = 0x0;
			RAX = R8;
			RCX = _rotl64(RCX, 0x10);
			R8 = 0xB8A0811CFC60168E;
			RAX ^= R8;
			RCX ^= R10;
			RCX = ~RCX;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RAX = 0x3CEF03F81E1AEBCF;
			R8 *= RAX;
			RAX = 0x6C597BE0239E08F2;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x18;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x30;
			R8 ^= RAX;
			return R8;
		}
		case 3: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = 0xF93AD4ADE7DED26B;
			R8 *= RAX;
			RAX = imageBase + 0x5651841B;
			RAX = ~RAX;
			RAX++;
			RAX += RBX;
			R8 ^= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = imageBase + 0x9EB5;
			RAX = ~RAX;
			RAX *= RBX;
			R8 += RAX;
			RAX = imageBase;
			R8 -= RAX;
			RAX = R8;
			RAX >>= 0x1F;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x3E;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x11;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x22;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			R8 *= readMemory<uint64_t>(RAX + 0x19);
			return R8;
		}
		case 4: {
			uint64_t RBP_NEG_0x60 = imageBase;
			RAX = 0x9492EF85F5F7F013;
			RBP_NEG_0x60 = RAX; // mov [rbp-60h],rax
			R9 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = R8;
			RAX >>= 0xA;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x14;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x28;
			R8 ^= RAX;
			RAX = 0x2475CFAEDE7F6DD0;
			R8 -= RAX;
			RAX = 0xD114CD7665FC2E4C;
			R8 ^= RAX;
			RAX = imageBase;
			R8 -= RAX;
			RAX = imageBase + 0xA2E1;
			RAX = ~RAX;
			RAX ^= RBX;
			R8 -= RAX;
			RAX = imageBase;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R9;
			RAX = ~RAX;
			RAX = readMemory<uint64_t>(RAX + 0x19);
			RAX *= RBP_NEG_0x60; // imul rax,[rbp-60h]
			R8 *= RAX;
			return R8;
		}
		case 5: {
			// push rbx
			// pushfq
			// pop rbx
			// popfq
			// pop rbx
			R11 = readMemory<uint64_t>(imageBase + 0x7420216);
			R8 = R8 + RBX * 2;
			R8 += 0xFFFFFFFF938F81BB;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R11;
			RAX = ~RAX;
			R8 *= readMemory<uint64_t>(RAX + 0x19);
			RAX = imageBase;
			R8 -= RAX;
			RAX = imageBase;
			RAX += 0xED8E;
			RAX += RBX;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x16;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2C;
			R8 ^= RAX;
			RAX = 0x9D3E9E6D1D6DA82B;
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
		case 6: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = imageBase;
			R8 -= RAX;
			R8 += 0xFFFFFFFFFFFF8104;
			R8 += RBX;
			RAX = 0x4907E05B52C3E160;
			R8 -= RAX;
			RAX = imageBase;
			RAX += 0xDD7B;
			RAX += RBX;
			R8 += RAX;
			RAX = imageBase;
			RAX += 0x245B;
			RAX += RBX;
			R8 ^= RAX;
			RAX = 0xB0E7E4F7BB271F8F;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			R8 *= readMemory<uint64_t>(RAX + 0x19);
			return R8;
		}
		case 7: {
			R9 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = 0x5F374DCA8F3D13C9;
			R8 *= RAX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R9;
			RAX = ~RAX;
			R8 *= readMemory<uint64_t>(RAX + 0x19);
			RAX = imageBase + 0x5C95149D;
			RAX = ~RAX;
			RAX += RBX;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x1A;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x34;
			R8 ^= RAX;
			RAX = 0x75370FCB0114A0E4;
			R8 ^= RAX;
			RAX = imageBase;
			R8 -= RAX;
			RAX = 0x6E0D44EBF8285199;
			R8 *= RAX;
			RAX = imageBase;
			R8 += RAX;
			return R8;
		}
		case 8: {
			uint64_t RBP_NEG_0x68 = imageBase;
			uint64_t RSP_0x70 = imageBase;
			// push rax
			// pushfq
			// pop rax
			// popfq
			// pop rax
			RAX = imageBase + 0x8AB7;
			RSP_0x70 = RAX; // mov [rsp+70h],rax
			RAX = imageBase + 0x6601953E;
			RBP_NEG_0x68 = RAX; // mov [rbp-68h],rax
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = R8;
			RAX >>= 0xB;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x16;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2C;
			R8 ^= RAX;
			RAX = RBX;
			RAX *= RSP_0x70; // imul rax,[rsp+70h]
			RAX += R8;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RCX = ~RCX;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			R8 -= RBX;
			RAX = RBX;
			RAX = ~RAX;
			RAX ^= RBP_NEG_0x68; // xor rax,[rbp-68h]
			R8 += RAX;
			RAX = 0xCDB430531A7EF0B9;
			R8 ^= RAX;
			RAX = 0xD76994438B37B4BB;
			R8 *= RAX;
			RAX = 0x2B07A4699A8F5064;
			R8 += RAX;
			return R8;
		}
		case 9: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RCX = RBX;
			RCX = ~RCX;
			RAX = imageBase + 0xF121;
			RAX = ~RAX;
			RCX *= RAX;
			R8 ^= RCX;
			RAX = R8;
			RAX >>= 0x17;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x2E;
			R8 ^= RAX;
			RAX = 0x45D142D1F96799A9;
			R8 *= RAX;
			RAX = 0x40B326AB9F64C016;
			R8 += RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RAX = imageBase;
			RAX += 0x365FF8D4;
			RCX = ~RCX;
			RAX += RBX;
			RAX ^= R8;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x1;
			R8 ^= RAX;
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
			RAX = 0xA4867805F8F141E0;
			R8 ^= RAX;
			return R8;
		}
		case 10: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RCX = 0x0;
			RAX = RBX + R8;
			RCX = _rotl64(RCX, 0x10);
			R8 = imageBase + 0x6725635F;
			RAX += R8;
			RCX ^= R10;
			RCX = ~RCX;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RAX = 0x391FA0E090F7D6F9;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0xC;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x18;
			R8 ^= RAX;
			RAX = imageBase;
			RCX = RAX * 2 + 0x10B490FB;
			RAX = R8;
			RAX >>= 0x30;
			R8 ^= RAX;
			RCX *= RBX;
			R8 += RCX;
			RAX = 0xC4B7AA591510D7EB;
			R8 *= RAX;
			RAX = 0x3F5B7E02642C0C27;
			R8 ^= RAX;
			return R8;
		}
		case 11: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RCX ^= R10;
			RAX = imageBase;
			RAX += R8;
			RCX = ~RCX;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RCX = imageBase + 0xFE80;
			R8 ^= RBX;
			RAX = 0xAD9B540D05C9A603;
			R8 *= RAX;
			RAX = 0x31E0824A0A52C7AF;
			R8 += RAX;
			R11 = 0x82F93DB709A0AC9;
			RAX = RBX;
			RAX = ~RAX;
			RAX ^= RCX;
			RAX += R11;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x10;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			return R8;
		}
		case 12: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = 0x57BAA633092881A5;
			R8 *= RAX;
			RAX = 0xE44D2AD9E560B4A;
			R8 += RAX;
			R8 += RBX;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			R8 *= readMemory<uint64_t>(RAX + 0x19);
			RAX = imageBase;
			RAX += 0x10D0;
			RAX += RBX;
			R8 ^= RAX;
			RAX = 0xE0E83D1511BE7AC7;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x28;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x24;
			R8 ^= RAX;
			return R8;
		}
		case 13: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = 0x859F70F5004FE0C9;
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x17;
			R8 ^= RAX;
			RCX = 0x0;
			RCX = _rotl64(RCX, 0x10);
			RAX = R8;
			RCX ^= R10;
			RAX >>= 0x2E;
			RCX = ~RCX;
			RAX ^= R8;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RAX = imageBase + 0x314CB44B;
			R8 += RAX;
			RAX = R8;
			RAX >>= 0x14;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x28;
			R8 ^= RAX;
			RAX = 0x707648592D402A3A;
			R8 += RAX;
			return R8;
		}
		case 14: {
			uint64_t RBP_NEG_0x38 = imageBase;
			uint64_t RSP_0x60 = imageBase;
			// pushfq
			// push rbx
			// pop rbx
			// pop rbx
			// popfq
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RAX = imageBase + 0x31C944AA;
			RSP_0x60 = RAX; // mov [rsp+60h],rax
			RAX = imageBase;
			RAX += 0x7587A163;
			RAX += RBX;
			R8 ^= RAX;
			RAX = RBX;
			RAX *= RSP_0x60; // imul rax,[rsp+60h]
			R8 -= RAX;
			RAX = 0x9C86D8FDDD758499;
			R8 *= RAX;
			RCX = 0x0;
			RAX = RBX;
			RAX = ~RAX;
			RCX = _rotl64(RCX, 0x10);
			RAX -= RBP_NEG_0x38; // sub rax,[rbp-38h]
			RCX ^= R10;
			RAX += 0xFFFFFFFF83DAA192;
			RCX = ~RCX;
			RAX += R8;
			R8 = readMemory<uint64_t>(RCX + 0x19);
			R8 *= RAX;
			RAX = R8;
			RAX >>= 0x11;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x22;
			R8 ^= RAX;
			RAX = imageBase + 0xC085;
			RCX = RBX;
			R8 += RAX;
			RCX = ~RCX;
			R8 += RCX;
			return R8;
		}
		case 15: {
			R10 = readMemory<uint64_t>(imageBase + 0x7420216);
			RSI = 0xDEB658F4F12A709;
			RAX = imageBase;
			R8 -= RAX;
			RAX = R8;
			RAX >>= 0x10;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x20;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x13;
			R8 ^= RAX;
			RAX = R8;
			RAX >>= 0x26;
			R8 ^= RAX;
			R8 += RSI;
			RAX = 0x0;
			RAX = _rotl64(RAX, 0x10);
			RAX ^= R10;
			RAX = ~RAX;
			RCX = readMemory<uint64_t>(RAX + 0x19);
			RAX = 0x985761100FB39415;
			R8 *= RAX;
			RAX = 0x6C8740822E9A28DE;
			R8 -= RAX;
			R8 *= RCX;
			RAX = imageBase;
			R8 -= RAX;
			return R8;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

		RBX = index;
		RCX = RBX * 0x13C8;
		RAX = 0xF4CB515E7513FDBB;
		R11 = imageBase;
		RAX = _umul128(RAX, RCX, &RDX);
		R10 = 0xCAEFE5D7135F4681;
		RDX >>= 0xD;
		RAX = RDX * 0x2177;
		RCX -= RAX;
		RAX = 0x377AEF2669DE1559;
		R8 = RCX * 0x2177;
		RAX = _umul128(RAX, R8, &RDX);
		RDX >>= 0xB;
		RAX = RDX * 0x24EA;
		R8 -= RAX;
		RAX = 0xA41A41A41A41A41B;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = R8;
		RAX -= RDX;
		RAX >>= 0x1;
		RAX += RDX;
		RAX >>= 0x5;
		RCX = RAX * 0x27;
		RAX = 0xBD69104707661AA3;
		RAX = _umul128(RAX, R8, &RDX);
		RDX >>= 0x8;
		RCX += RDX;
		RAX = RCX * 0x2B4;
		RCX = R8 * 0x2B6;
		RCX -= RAX;
		RAX = readMemory<uint16_t>(RCX + R11 + 0x742EC10);
		R8 = RAX * 0x13C8;
		RAX = R10;
		RAX = _umul128(RAX, R8, &RDX);
		RAX = R10;
		RDX >>= 0xC;
		RCX = RDX * 0x142F;
		R8 -= RCX;
		R9 = R8 * 0x20AF;
		RAX = _umul128(RAX, R9, &RDX);
		RDX >>= 0xC;
		RAX = RDX * 0x142F;
		R9 -= RAX;
		RAX = 0xAAAAAAAAAAAAAAAB;
		RAX = _umul128(RAX, R9, &RDX);
		RAX = 0x41BBB2F80A4553F7;
		RDX >>= 0x2;
		RCX = RDX + RDX * 2;
		RAX = _umul128(RAX, R9, &RDX);
		RDX >>= 0x8;
		RAX = RDX + RCX * 2;
		RCX = RAX * 0x7CA;
		RAX = R9 * 0x7CC;
		RAX -= RCX;
		R15 = readMemory<uint16_t>(RAX + R11 + 0x7435580);
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