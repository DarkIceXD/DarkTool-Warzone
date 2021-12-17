#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = driver::read<uintptr_t>(imageBase + 0x1EB678B8);
		if (!rbx)
			return rbx;
		rdx = ~peb;              //mov rdx, gs:[rax]
		r8 = imageBase;
		rcx = rdx;              //mov rcx, rdx
		rax = imageBase + 0x1740D79E;              //lea rax, [0x00000000151A30B0]
		rcx = ~rcx;             //not rcx
		rcx += rax;             //add rcx, rax
		rcx ^= rbx;             //xor rcx, rbx
		rcx -= rdx;             //sub rcx, rdx
		rcx -= r8;              //sub rcx, r8
		rcx -= 0xF13A;          //sub rcx, 0xF13A
		rax = rcx;              //mov rax, rcx
		rax >>= 0x13;           //shr rax, 0x13
		rcx ^= rax;             //xor rcx, rax
		rbx = rcx;              //mov rbx, rcx
		rax = 0;                //and rax, 0xFFFFFFFFC0000000
		rbx >>= 0x26;           //shr rbx, 0x26
		rax = _rotl64(rax, 0x10);               //rol rax, 0x10
		rbx ^= rcx;             //xor rbx, rcx
		rax ^= driver::read<uintptr_t>(imageBase + 0x72AF124);             //xor rax, [0x00000000050449EA]
		rax = _byteswap_uint64(rax);            //bswap rax
		rbx *= driver::read<uintptr_t>(rax + 0x7);              //imul rbx, [rax+0x07]
		rax = 0x7D037367013E30B7;               //mov rax, 0x7D037367013E30B7
		rbx *= rax;             //imul rbx, rax
		return rbx;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rax = driver::read<uintptr_t>(clientInfo + 0xa2c08);
		if (!rax)
			return rax;
		r11 = ~peb;              //mov r11, gs:[rcx]
		rcx = r11;              //mov rcx, r11
		rcx = _rotl64(rcx, 0x2D);               //rol rcx, 0x2D
		rcx &= 0xF;
		switch (rcx) {
		case 0:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x000000000504491C]
			rax += r11;             //add rax, r11
			rax ^= r11;             //xor rax, r11
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = 0x5098DC4F4C0E1456;               //mov rcx, 0x5098DC4F4C0E1456
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x8;            //shr rcx, 0x08
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x8;            //shr rcx, 0x08
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x8889B521E2298BF;                //mov rcx, 0x8889B521E2298BF
			rax *= rcx;             //imul rax, rcx
			rcx = 0x9D4E09B4BA23203C;               //mov rcx, 0x9D4E09B4BA23203C
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 1:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005044454]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xEA238BD6461ABAF7;               //mov rcx, 0xEA238BD6461ABAF7
			rax *= rcx;             //imul rax, rcx
			rcx = 0x1372427E917528C7;               //mov rcx, 0x1372427E917528C7
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x15;           //shr rcx, 0x15
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2A;           //shr rcx, 0x2A
			rax ^= rcx;             //xor rax, rcx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = imageBase + 0xC635;          //lea rcx, [0xFFFFFFFFFDDA16EE]
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rcx = ~rcx;             //not rcx
			rcx -= r11;             //sub rcx, r11
			rdx ^= r10;             //xor rdx, r10
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x7DBE77980F71921;                //mov rcx, 0x7DBE77980F71921
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= driver::read<uintptr_t>(rdx + 0x15);             //imul rax, [rdx+0x15]
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 2:
		{
			rsi = imageBase + 0x78E8;          //lea rsi, [0xFFFFFFFFFDD9C6CE]
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x0000000005043EFC]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = r11;              //mov rcx, r11
			rcx *= rsi;             //imul rcx, rsi
			rax -= rcx;             //sub rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1F;           //shr rcx, 0x1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3E;           //shr rcx, 0x3E
			rcx ^= r11;             //xor rcx, r11
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x3BBFDD253C49C413;               //mov rcx, 0x3BBFDD253C49C413
			rax *= rcx;             //imul rax, rcx
			rcx = 0x1070A91C697B241F;               //mov rcx, 0x1070A91C697B241F
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD94D27]
			rax -= r11;             //sub rax, r11
			rax -= rcx;             //sub rax, rcx
			rax -= 0x6CFA0C83;              //sub rax, 0x6CFA0C83
			return rax;
		}
		case 3:
		{
			r14 = imageBase + 0x1FD5;          //lea r14, [0xFFFFFFFFFDD969D0]
			r15 = imageBase + 0xB6C4;          //lea r15, [0xFFFFFFFFFDDA00B3]
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005043AE7]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x8;            //shr rcx, 0x08
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x1896B4723B1B5F77;               //mov rcx, 0x1896B4723B1B5F77
			rax ^= r15;             //xor rax, r15
			rax *= rcx;             //imul rax, rcx
			rcx = 0x345ABA373AA2B7F9;               //mov rcx, 0x345ABA373AA2B7F9
			rcx += r11;             //add rcx, r11
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rax += rcx;             //add rax, rcx
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= driver::read<uintptr_t>(rdx + 0x15);             //imul rax, [rdx+0x15]
			rcx = r11;              //mov rcx, r11
			rcx *= r14;             //imul rcx, r14
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x68FEF17A11FA23FD;               //mov rcx, 0x68FEF17A11FA23FD
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 4:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005043674]
			r15 = imageBase + 0x61141C60;              //lea r15, [0x000000005EED616A]
			r14 = imageBase + 0x252B;          //lea r14, [0xFFFFFFFFFDD96A29]
			rcx = rax;              //mov rcx, rax
			rdx = r14;              //mov rdx, r14
			rax = 0x19686DDAB1727027;               //mov rax, 0x19686DDAB1727027
			rdx = ~rdx;             //not rdx
			rcx *= rax;             //imul rcx, rax
			rdx *= r11;             //imul rdx, r11
			rax = rdx;              //mov rax, rdx
			rax ^= rcx;             //xor rax, rcx
			rdx = imageBase + 0x5519D26F;              //lea rdx, [0x0000000052F3171C]
			rax ^= r11;             //xor rax, r11
			rax ^= rdx;             //xor rax, rdx
			rcx = 0x676B5507FDF05649;               //mov rcx, 0x676B5507FDF05649
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x21;           //shr rcx, 0x21
			rax ^= rcx;             //xor rax, rcx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = r15;              //mov rcx, r15
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rcx = ~rcx;             //not rcx
			rcx -= r11;             //sub rcx, r11
			rdx ^= r10;             //xor rdx, r10
			rax ^= rcx;             //xor rax, rcx
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= driver::read<uintptr_t>(rdx + 0x15);             //imul rax, [rdx+0x15]
			rcx = 0xADA74FF63D43964D;               //mov rcx, 0xADA74FF63D43964D
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 5:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x00000000050430F9]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD93E53]
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xF;            //shr rcx, 0x0F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x633A680B5F0FC20B;               //mov rcx, 0x633A680B5F0FC20B
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x5;            //shr rcx, 0x05
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xA;            //shr rcx, 0x0A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x92C32D87B1D53631;               //mov rcx, 0x92C32D87B1D53631
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD93BF7]
			rcx += 0x71140A4C;              //add rcx, 0x71140A4C
			rcx += r11;             //add rcx, r11
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x4981D2728760C3F7;               //mov rcx, 0x4981D2728760C3F7
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			return rax;
		}
		case 6:
		{
			r15 = imageBase + 0x75C2ACB2;              //lea r15, [0x00000000739BE777]
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005042BAC]
			rcx = 0x217245148E2C2CDF;               //mov rcx, 0x217245148E2C2CDF
			rax *= rcx;             //imul rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xC703B3D0E6B048C3;               //mov rcx, 0xC703B3D0E6B048C3
			rax *= rcx;             //imul rax, rcx
			rax ^= r11;             //xor rax, r11
			rax ^= r15;             //xor rax, r15
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = 0x3A293018A836304D;               //mov rcx, 0x3A293018A836304D
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rdx ^= r10;             //xor rdx, r10
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= driver::read<uintptr_t>(rdx + 0x15);             //imul rax, [rdx+0x15]
			rdx = imageBase + 0x7B8D;          //lea rdx, [0xFFFFFFFFFDD9B48A]
			rcx = r11;              //mov rcx, r11
			rcx ^= rdx;             //xor rcx, rdx
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 7:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x0000000005042777]
			r10 = imageBase + 0x1BAED0C3;              //lea r10, [0x00000000198806D0]
			r15 = imageBase;           //lea r15, [0xFFFFFFFFFDD9354B]
			rcx = r11;              //mov rcx, r11
			rcx -= r15;             //sub rcx, r15
			rcx -= 0x62225603;              //sub rcx, 0x62225603
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x3BD827E0921DA442;               //mov rcx, 0x3BD827E0921DA442
			rax -= rcx;             //sub rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = 0x1A7736DC7DF34B49;               //mov rcx, 0x1A7736DC7DF34B49
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xC9D72E55A0C72075;               //mov rcx, 0xC9D72E55A0C72075
			rax *= rcx;             //imul rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx ^= r10;             //xor rcx, r10
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 8:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005042380]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD92D6B]
			rax ^= rcx;             //xor rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			rax += rcx;             //add rax, rcx
			rcx = imageBase + 0x4874;          //lea rcx, [0xFFFFFFFFFDD975CC]
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = 0x8DB340B078A74BB9;               //mov rcx, 0x8DB340B078A74BB9
			rax *= rcx;             //imul rax, rcx
			rcx = 0x662C53AA617F463B;               //mov rcx, 0x662C53AA617F463B
			rax += rcx;             //add rax, rcx
			rax -= r11;             //sub rax, r11
			return rax;
		}
		case 9:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x0000000005041DBA]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD929AF]
			rcx += 0x4D5F;          //add rcx, 0x4D5F
			rcx += r11;             //add rcx, r11
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xF;            //shr rcx, 0x0F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			rax += r11;             //add rax, r11
			rcx = 0x20AB1EFCD0B1EB91;               //mov rcx, 0x20AB1EFCD0B1EB91
			rax ^= rcx;             //xor rax, rcx
			rsi = imageBase;           //lea rsi, [0xFFFFFFFFFDD929EE]
			rcx = 0xDBA0890CC53FF4FF;               //mov rcx, 0xDBA0890CC53FF4FF
			rax *= rcx;             //imul rax, rcx
			rcx = 0x4288955A707A9CEF;               //mov rcx, 0x4288955A707A9CEF
			rax += rcx;             //add rax, rcx
			rax += rsi;             //add rax, rsi
			return rax;
		}
		case 10:
		{
			r14 = imageBase + 0x3D70E030;              //lea r14, [0x000000003B4A0795]
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005041854]
			rcx = r11;              //mov rcx, r11
			uintptr_t RSP_0x60;
			RSP_0x60 = imageBase + 0x6230;             //lea rcx, [0xFFFFFFFFFDD98970] : RSP+0x60
			rcx *= RSP_0x60;                //imul rcx, [rsp+0x60]
			rax += rcx;             //add rax, rcx
			rax += r14;             //add rax, r14
			rdx = r11;              //mov rdx, r11
			rdx = ~rdx;             //not rdx
			rax += rdx;             //add rax, rdx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x23;           //shr rcx, 0x23
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x629FDB45D83ACF99;               //mov rcx, 0x629FDB45D83ACF99
			rax *= rcx;             //imul rax, rcx
			rax ^= r11;             //xor rax, r11
			rcx = 0x95CEAC06FDAFC6CD;               //mov rcx, 0x95CEAC06FDAFC6CD
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = 0x5441205014F7F037;               //mov rcx, 0x5441205014F7F037
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 11:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005041451]
			r15 = imageBase + 0x4E012628;              //lea r15, [0x000000004BDA490F]
			r14 = imageBase + 0x56F0;          //lea r14, [0xFFFFFFFFFDD979CC]
			rax ^= r11;             //xor rax, r11
			rax ^= r14;             //xor rax, r14
			rcx = 0x23C534834E590797;               //mov rcx, 0x23C534834E590797
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD91E67]
			rax += rcx;             //add rax, rcx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			rcx *= r15;             //imul rcx, r15
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax += rcx;             //add rax, rcx
			rax *= driver::read<uintptr_t>(rdx + 0x15);             //imul rax, [rdx+0x15]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x26;           //shr rcx, 0x26
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rax ^= rcx;             //xor rax, rcx
			rax -= r11;             //sub rax, r11
			return rax;
		}
		case 12:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x0000000005040F71]
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			uintptr_t RSP_0xFFFFFFFFFFFFFF88;
			RSP_0xFFFFFFFFFFFFFF88 = imageBase + 0x37C3F569;           //lea rcx, [0x00000000359D137C] : RBP+0xFFFFFFFFFFFFFF88
			rcx *= RSP_0xFFFFFFFFFFFFFF88;          //imul rcx, [rbp-0x78]
			rax += rcx;             //add rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx -= imageBase;          //sub rcx, [rbp-0x80] -- didn't find trace -> use base
			rcx += 0xFFFFFFFFFFFFEE2C;              //add rcx, 0xFFFFFFFFFFFFEE2C
			rax += rcx;             //add rax, rcx
			rcx = 0x4FF4C01916651419;               //mov rcx, 0x4FF4C01916651419
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rcx = driver::read<uintptr_t>(rcx + 0x15);              //mov rcx, [rcx+0x15]
			uintptr_t RSP_0x48;
			RSP_0x48 = 0xCB32221DE51BF37;           //mov rcx, 0xCB32221DE51BF37 : RSP+0x48
			rcx *= RSP_0x48;                //imul rcx, [rsp+0x48]
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x7;            //shr rcx, 0x07
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xFFFFFFFF918D89B7;               //mov rcx, 0xFFFFFFFF918D89B7
			rcx -= r11;             //sub rcx, r11
			rcx -= imageBase;          //sub rcx, [rbp-0x80] -- didn't find trace -> use base
			rax += rcx;             //add rax, rcx
			rcx = 0xE53E777C9B49B8C;                //mov rcx, 0xE53E777C9B49B8C
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 13:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x000000000504093B]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD91724]
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x8611E269817EE1B3;               //mov rcx, 0x8611E269817EE1B3
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = 0x746B6E1C295D372;                //mov rcx, 0x746B6E1C295D372
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD91387]
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x4;            //shr rcx, 0x04
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x8;            //shr rcx, 0x08
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1D;           //shr rcx, 0x1D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3A;           //shr rcx, 0x3A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x35CE80F541F75ED0;               //mov rcx, 0x35CE80F541F75ED0
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 14:
		{
			r14 = imageBase + 0x39094B30;              //lea r14, [0x0000000036E25DFD]
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF157);               //mov r9, [0x00000000050403B5]
			rcx = 0x4F984FD0F88E1E18;               //mov rcx, 0x4F984FD0F88E1E18
			rax -= rcx;             //sub rax, rcx
			//failed to translate: inc rax
			rcx = r14;              //mov rcx, r14
			rcx = ~rcx;             //not rcx
			rcx += r11;             //add rcx, r11
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x22;           //shr rcx, 0x22
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xE2478769402024E1;               //mov rcx, 0xE2478769402024E1
			rax *= rcx;             //imul rax, rcx
			rcx = 0x7A07D33B1B737C94;               //mov rcx, 0x7A07D33B1B737C94
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x25;           //shr rcx, 0x25
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 15:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF157);              //mov r10, [0x000000000503FF18]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD90946]
			rax -= rcx;             //sub rax, rcx
			rcx = imageBase + 0x558D7463;              //lea rcx, [0x0000000053668017]
			rax += rcx;             //add rax, rcx
			rdx = r11;              //mov rdx, r11
			rdx = ~rdx;             //not rdx
			rax += rdx;             //add rax, rdx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDD909C6]
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xC48FC9D4011610BD;               //mov rcx, 0xC48FC9D4011610BD
			rax *= rcx;             //imul rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x7;            //shr rcx, 0x07
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			r14 = 0xA95627D4EAF11D8D;               //mov r14, 0xA95627D4EAF11D8D
			rax += r14;             //add rax, r14
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x15);             //imul rax, [rcx+0x15]
			return rax;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		r8 = driver::read<uintptr_t>(imageBase + 0x1BCF6B48);
		if (!r8)
			return r8;
		rbx = ~peb;              //mov rbx, gs:[rax]
		rax = rbx;              //mov rax, rbx
		rax = _rotl64(rax, 0x21);               //rol rax, 0x21
		rax &= 0xF;
		switch (rax) {
		case 0:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF269);               //mov r9, [0x0000000004EDF09B]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = 0xFFFFFFFF8D4F0082;               //mov rax, 0xFFFFFFFF8D4F0082
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDC2FC89]
			rax -= rbx;             //sub rax, rbx
			rax -= r11;             //sub rax, r11
			r8 += rax;              //add r8, rax
			r11 = imageBase + 0x9DA3;          //lea r11, [0xFFFFFFFFFDC39B8A]
			rax = rbx;              //mov rax, rbx
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x18;           //shr rax, 0x18
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x30;           //shr rax, 0x30
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2FA4F]
			r8 -= rax;              //sub r8, rax
			rax = 0xF8223C958390731B;               //mov rax, 0xF8223C958390731B
			r8 *= rax;              //imul r8, rax
			rax = 0xAD1C5D88470601FD;               //mov rax, 0xAD1C5D88470601FD
			r8 += rax;              //add r8, rax
			rax = 0xD5A842AB557F3D9A;               //mov rax, 0xD5A842AB557F3D9A
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 1:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDEBCA]
			rcx = imageBase + 0xB372;          //lea rcx, [0xFFFFFFFFFDC3AC83]
			rax = rbx;              //mov rax, rbx
			rax ^= rcx;             //xor rax, rcx
			r8 -= rax;              //sub r8, rax
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDC2F59F]
			rax = imageBase + 0x6AD453A2;              //lea rax, [0x0000000068974916]
			rax = ~rax;             //not rax
			rax ^= rbx;             //xor rax, rbx
			rax -= r11;             //sub rax, r11
			r8 += rax;              //add r8, rax
			rax = 0x9B018290D9E4AA59;               //mov rax, 0x9B018290D9E4AA59
			r8 *= rax;              //imul r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x26;           //shr rax, 0x26
			r8 ^= rax;              //xor r8, rax
			rax = 0x57B808FF05967115;               //mov rax, 0x57B808FF05967115
			r8 += rax;              //add r8, rax
			rax = 0xAD51013A881770EF;               //mov rax, 0xAD51013A881770EF
			r8 *= rax;              //imul r8, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			return r8;
		}
		case 2:
		{
			//failed to translate: pop rbx
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDE76D]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = r8;               //mov rax, r8
			rax >>= 0x16;           //shr rax, 0x16
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2C;           //shr rax, 0x2C
			r8 ^= rax;              //xor r8, rax
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rax = imageBase + 0xFD61;          //lea rax, [0xFFFFFFFFFDC3ED47]
			rcx *= rax;             //imul rcx, rax
			rax = r8;               //mov rax, r8
			r8 = 0x6D8627334D164F1;                 //mov r8, 0x6D8627334D164F1
			r8 *= rax;              //imul r8, rax
			r8 += rcx;              //add r8, rcx
			rax = r8;               //mov rax, r8
			rax >>= 0x1;            //shr rax, 0x01
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2;            //shr rax, 0x02
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x4;            //shr rax, 0x04
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x8;            //shr rax, 0x08
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x10;           //shr rax, 0x10
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x20;           //shr rax, 0x20
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x15;           //shr rax, 0x15
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2A;           //shr rax, 0x2A
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 3:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDE11D]
			rax = r8;               //mov rax, r8
			rax >>= 0x17;           //shr rax, 0x17
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2E;           //shr rax, 0x2E
			r8 ^= rax;              //xor r8, rax
			rax = 0xFE574E233B2A1CFC;               //mov rax, 0xFE574E233B2A1CFC
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2EB19]
			r8 += rax;              //add r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x13;           //shr rax, 0x13
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x26;           //shr rax, 0x26
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			r8 ^= rax;              //xor r8, rax
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2ECE2]
			rcx ^= r10;             //xor rcx, r10
			r8 ^= rax;              //xor r8, rax
			rcx = ~rcx;             //not rcx
			rax = 0xB1B628BF2CC88CF5;               //mov rax, 0xB1B628BF2CC88CF5
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			r8 *= rax;              //imul r8, rax
			return r8;
		}
		case 4:
		{
			//failed to translate: pop rbx
			r11 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r11, [0x0000000004EDDBD2]
			rax = 0x6A477414A347C06F;               //mov rax, 0x6A477414A347C06F
			r8 *= rax;              //imul r8, rax
			rax = 0xCCC1F0196522B225;               //mov rax, 0xCCC1F0196522B225
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xC;            //shr rax, 0x0C
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x18;           //shr rax, 0x18
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x30;           //shr rax, 0x30
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2E750]
			rax += 0xA110;          //add rax, 0xA110
			rax += rbx;             //add rax, rbx
			r8 += rax;              //add r8, rax
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r11;             //xor rax, r11
			rax = ~rax;             //not rax
			rdx = driver::read<uintptr_t>(rax + 0xd);               //mov rdx, [rax+0x0D]
			rax = imageBase + 0x5B1B3622;              //lea rax, [0x0000000058DE1C3F]
			rax = ~rax;             //not rax
			rcx += rax;             //add rcx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2E608]
			rcx -= rax;             //sub rcx, rax
			rax = 0xF56CDF71E1A5D93D;               //mov rax, 0xF56CDF71E1A5D93D
			rcx += rbx;             //add rcx, rbx
			r8 += rcx;              //add r8, rcx
			r8 *= rax;              //imul r8, rax
			rax = 0x61F801A7637D1AF9;               //mov rax, 0x61F801A7637D1AF9
			r8 += rax;              //add r8, rax
			r8 *= rdx;              //imul r8, rdx
			return r8;
		}
		case 5:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF269);               //mov r9, [0x0000000004EDD684]
			rax = r8;               //mov rax, r8
			rax >>= 0x17;           //shr rax, 0x17
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2E;           //shr rax, 0x2E
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2DFDB]
			rax += 0x5333;          //add rax, 0x5333
			rax += rbx;             //add rax, rbx
			r8 += rax;              //add r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x27;           //shr rax, 0x27
			r8 ^= rax;              //xor r8, rax
			r8 -= rbx;              //sub r8, rbx
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = 0xA59E5728885EEE93;               //mov rax, 0xA59E5728885EEE93
			r8 *= rax;              //imul r8, rax
			rax = 0x6EAFDEAD53F36EE8;               //mov rax, 0x6EAFDEAD53F36EE8
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 6:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDD14E]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = r8;               //mov rax, r8
			rax >>= 0x23;           //shr rax, 0x23
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x5;            //shr rax, 0x05
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xA;            //shr rax, 0x0A
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x14;           //shr rax, 0x14
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x28;           //shr rax, 0x28
			r8 ^= rax;              //xor r8, rax
			rax = 0xFB3A20DFA1FEC597;               //mov rax, 0xFB3A20DFA1FEC597
			r8 *= rax;              //imul r8, rax
			rax = 0x9D34BCD4BA58BB91;               //mov rax, 0x9D34BCD4BA58BB91
			r8 *= rax;              //imul r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2DC5E]
			r8 ^= rax;              //xor r8, rax
			rax = 0x6A21B4883F6DEEB6;               //mov rax, 0x6A21B4883F6DEEB6
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x14;           //shr rax, 0x14
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x28;           //shr rax, 0x28
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 7:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDCBBA]
			rax = r8;               //mov rax, r8
			rax >>= 0x1A;           //shr rax, 0x1A
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax >>= 0x34;           //shr rax, 0x34
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			r8 ^= rax;              //xor r8, rax
			rcx ^= r10;             //xor rcx, r10
			rax = 0xEFC9E5B644D8365B;               //mov rax, 0xEFC9E5B644D8365B
			rcx = ~rcx;             //not rcx
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			r8 *= rax;              //imul r8, rax
			rcx = imageBase + 0x4B76;          //lea rcx, [0xFFFFFFFFFDC32477]
			rax = 0xD97AE04D7B82C647;               //mov rax, 0xD97AE04D7B82C647
			r8 *= rax;              //imul r8, rax
			r8 -= rbx;              //sub r8, rbx
			rax = r8;               //mov rax, r8
			rax >>= 0xE;            //shr rax, 0x0E
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x1C;           //shr rax, 0x1C
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x38;           //shr rax, 0x38
			r8 ^= rax;              //xor r8, rax
			r8 -= rbx;              //sub r8, rbx
			r8 += rcx;              //add r8, rcx
			return r8;
		}
		case 8:
		{
			//failed to translate: pop rbx
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDC6E3]
			rax = 0xA0409E79A43A271B;               //mov rax, 0xA0409E79A43A271B
			r8 *= rax;              //imul r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x1;            //shr rax, 0x01
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2;            //shr rax, 0x02
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x4;            //shr rax, 0x04
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x8;            //shr rax, 0x08
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x10;           //shr rax, 0x10
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax >>= 0x20;           //shr rax, 0x20
			r8 ^= rax;              //xor r8, rax
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rax = 0x2DA1E695C439F6FC;               //mov rax, 0x2DA1E695C439F6FC
			rcx = ~rcx;             //not rcx
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x17;           //shr rax, 0x17
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2E;           //shr rax, 0x2E
			r8 ^= rax;              //xor r8, rax
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDC2D028]
			rax = rbx;              //mov rax, rbx
			rax = ~rax;             //not rax
			rax -= r11;             //sub rax, r11
			rax += 0xFFFFFFFF9BE0509E;              //add rax, 0xFFFFFFFF9BE0509E
			r8 += rax;              //add r8, rax
			rax = imageBase + 0x482BDCE4;              //lea rax, [0x0000000045EEB0A2]
			r8 ^= rax;              //xor r8, rax
			rax = 0x51549FB6ECBFB9A2;               //mov rax, 0x51549FB6ECBFB9A2
			r8 ^= rbx;              //xor r8, rbx
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 9:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDC153]
			r8 += rbx;              //add r8, rbx
			rax = r8;               //mov rax, r8
			rax >>= 0x19;           //shr rax, 0x19
			r8 ^= rax;              //xor r8, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rax = r8;               //mov rax, r8
			rcx = ~rcx;             //not rcx
			rax >>= 0x32;           //shr rax, 0x32
			r8 ^= rax;              //xor r8, rax
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			rax = 0xC3C1E7238826F0E3;               //mov rax, 0xC3C1E7238826F0E3
			r8 *= rax;              //imul r8, rax
			r8 ^= rbx;              //xor r8, rbx
			rax = imageBase + 0x85E1;          //lea rax, [0xFFFFFFFFFDC352AA]
			r8 ^= rax;              //xor r8, rax
			rax = 0x36919C1DAB4319F;                //mov rax, 0x36919C1DAB4319F
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2CCF7]
			r8 ^= rax;              //xor r8, rax
			rax = 0x3E644A0A1C4ABA44;               //mov rax, 0x3E644A0A1C4ABA44
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 10:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDBC49]
			r11 = imageBase + 0x272;           //lea r11, [0xFFFFFFFFFDC2CC3F]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2C6D7]
			r8 ^= rax;              //xor r8, rax
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2C678]
			r8 += rax;              //add r8, rax
			rax = 0x35F80BEE9E577B5D;               //mov rax, 0x35F80BEE9E577B5D
			r8 *= rax;              //imul r8, rax
			rax = 0xE81A7FABDAFAA67;                //mov rax, 0xE81A7FABDAFAA67
			r8 -= rax;              //sub r8, rax
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rcx += rax;             //add rcx, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x20;           //shr rax, 0x20
			rcx ^= rax;             //xor rcx, rax
			r8 ^= rcx;              //xor r8, rcx
			rax = r8;               //mov rax, r8
			rax >>= 0x19;           //shr rax, 0x19
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x32;           //shr rax, 0x32
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			r8 ^= rax;              //xor r8, rax
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			return r8;
		}
		case 11:
		{
			//failed to translate: pop rbx
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDB80D]
			rcx = imageBase + 0xAF0A;          //lea rcx, [0xFFFFFFFFFDC37443]
			rax = 0x900D58648B08FD67;               //mov rax, 0x900D58648B08FD67
			r8 *= rax;              //imul r8, rax
			rax = 0x26F4BB807BE0EAAF;               //mov rax, 0x26F4BB807BE0EAAF
			r8 -= rax;              //sub r8, rax
			rax = rbx;              //mov rax, rbx
			rax *= rcx;             //imul rax, rcx
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xE;            //shr rax, 0x0E
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x1C;           //shr rax, 0x1C
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x38;           //shr rax, 0x38
			r8 ^= rax;              //xor r8, rax
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDC2C0A5]
			rax = rbx;              //mov rax, rbx
			rax -= rcx;             //sub rax, rcx
			rax += 0xFFFFFFFFFFFF756A;              //add rax, 0xFFFFFFFFFFFF756A
			r8 += rax;              //add r8, rax
			rax = 0x23F739B05DBF5EB0;               //mov rax, 0x23F739B05DBF5EB0
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xB;            //shr rax, 0x0B
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x16;           //shr rax, 0x16
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x2C;           //shr rax, 0x2C
			r8 ^= rax;              //xor r8, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			return r8;
		}
		case 12:
		{
			//failed to translate: pop rbx
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF269);               //mov r9, [0x0000000004EDB1EC]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = 0x6A19C1C7E437843D;               //mov rax, 0x6A19C1C7E437843D
			r8 += rax;              //add r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x4;            //shr rax, 0x04
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x8;            //shr rax, 0x08
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x10;           //shr rax, 0x10
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x20;           //shr rax, 0x20
			r8 ^= rax;              //xor r8, rax
			rax = 0x593521E25A6758F7;               //mov rax, 0x593521E25A6758F7
			r8 *= rax;              //imul r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x18;           //shr rax, 0x18
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x30;           //shr rax, 0x30
			rax ^= rbx;             //xor rax, rbx
			r8 ^= rax;              //xor r8, rax
			rax = imageBase + 0xBABB;          //lea rax, [0xFFFFFFFFFDC375AF]
			r8 ^= rax;              //xor r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2BB4A]
			r8 += rax;              //add r8, rax
			r8 += rbx;              //add r8, rbx
			return r8;
		}
		case 13:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDAC97]
			rax = r8;               //mov rax, r8
			rax >>= 0x1B;           //shr rax, 0x1B
			r8 ^= rax;              //xor r8, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = r8;               //mov rax, r8
			rcx ^= r10;             //xor rcx, r10
			rax >>= 0x36;           //shr rax, 0x36
			rcx = ~rcx;             //not rcx
			r8 ^= rax;              //xor r8, rax
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2B574]
			r8 += rax;              //add r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x3;            //shr rax, 0x03
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x6;            //shr rax, 0x06
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xC;            //shr rax, 0x0C
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x18;           //shr rax, 0x18
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x30;           //shr rax, 0x30
			r8 ^= rax;              //xor r8, rax
			rax = 0xDC882EE398774B3A;               //mov rax, 0xDC882EE398774B3A
			r8 ^= rax;              //xor r8, rax
			rax = 0x71BC85CECC2CF7C7;               //mov rax, 0x71BC85CECC2CF7C7
			r8 -= rax;              //sub r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0xF;            //shr rax, 0x0F
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x1E;           //shr rax, 0x1E
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x3C;           //shr rax, 0x3C
			r8 ^= rax;              //xor r8, rax
			rax = 0xB22294677CAE4057;               //mov rax, 0xB22294677CAE4057
			r8 *= rax;              //imul r8, rax
			return r8;
		}
		case 14:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x72AF269);               //mov r9, [0x0000000004EDA6C5]
			rax = rbx;              //mov rax, rbx
			uintptr_t RSP_0xFFFFFFFFFFFFFFC0;
			RSP_0xFFFFFFFFFFFFFFC0 = imageBase + 0x5D2C829C;           //lea rax, [0x000000005AEF36F1] : RBP+0xFFFFFFFFFFFFFFC0
			rax ^= RSP_0xFFFFFFFFFFFFFFC0;          //xor rax, [rbp-0x40]
			r8 += rax;              //add r8, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFDC2B1A9]
			r8 -= rax;              //sub r8, rax
			rax = 0x2DFD83BA726131F3;               //mov rax, 0x2DFD83BA726131F3
			r8 *= rax;              //imul r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x1C;           //shr rax, 0x1C
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x38;           //shr rax, 0x38
			r8 ^= rax;              //xor r8, rax
			rax = 0xF4ECD7D0B27744D1;               //mov rax, 0xF4ECD7D0B27744D1
			r8 *= rax;              //imul r8, rax
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDC2B2E4]
			r8 += r11;              //add r8, r11
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			r8 *= driver::read<uintptr_t>(rax + 0xd);               //imul r8, [rax+0x0D]
			rax = 0xD42A25F92D1BC49F;               //mov rax, 0xD42A25F92D1BC49F
			r8 ^= rax;              //xor r8, rax
			return r8;
		}
		case 15:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x72AF269);              //mov r10, [0x0000000004EDA125]
			rax = r8;               //mov rax, r8
			rax >>= 0x1D;           //shr rax, 0x1D
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x3A;           //shr rax, 0x3A
			r8 ^= rax;              //xor r8, rax
			rax = imageBase + 0x18571ADD;              //lea rax, [0x000000001619C648]
			rax = ~rax;             //not rax
			rax *= rbx;             //imul rax, rbx
			r8 += rax;              //add r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x4;            //shr rax, 0x04
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x8;            //shr rax, 0x08
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x10;           //shr rax, 0x10
			r8 ^= rax;              //xor r8, rax
			rax = r8;               //mov rax, r8
			rax >>= 0x20;           //shr rax, 0x20
			r8 ^= rax;              //xor r8, rax
			rax = rbx;              //mov rax, rbx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			r8 *= driver::read<uintptr_t>(rcx + 0xd);               //imul r8, [rcx+0x0D]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFDC2ACA5]
			rax -= rcx;             //sub rax, rcx
			rax -= 0x60AAD3EF;              //sub rax, 0x60AAD3EF
			r8 ^= rax;              //xor r8, rax
			rax = 0x4787A3D03756D75D;               //mov rax, 0x4787A3D03756D75D
			r8 ^= rax;              //xor r8, rax
			rax = 0x6A58CF259205070B;               //mov rax, 0x6A58CF259205070B
			r8 *= rax;              //imul r8, rax
			rax = 0x23040926EA571BB0;               //mov rax, 0x23040926EA571BB0
			r8 += rax;              //add r8, rax
			return r8;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = index;
		rcx = rbx * 0x13C8;
		rax = 0xC9C400975300717F;               //mov rax, 0xC9C400975300717F
		r11 = imageBase;           //lea r11, [0xFFFFFFFFFDDA953D]
		rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
		r10 = 0x26EAA6D39C7E93F7;               //mov r10, 0x26EAA6D39C7E93F7
		rdx >>= 0xC;            //shr rdx, 0x0C
		rax = rdx * 0x144D;             //imul rax, rdx, 0x144D
		rcx -= rax;             //sub rcx, rax
		rax = 0x4AC525D2BAA21969;               //mov rax, 0x4AC525D2BAA21969
		r8 = rcx * 0x144D;              //imul r8, rcx, 0x144D
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rdx >>= 0xB;            //shr rdx, 0x0B
		rax = rdx * 0x1B64;             //imul rax, rdx, 0x1B64
		r8 -= rax;              //sub r8, rax
		rax = 0xE60D414382A3C6F;                //mov rax, 0xE60D414382A3C6F
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = 0xAAAAAAAAAAAAAAAB;               //mov rax, 0xAAAAAAAAAAAAAAAB
		rdx >>= 0x7;            //shr rdx, 0x07
		rcx = rdx * 0x8E7;              //imul rcx, rdx, 0x8E7
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rdx >>= 0x2;            //shr rdx, 0x02
		rcx += rdx;             //add rcx, rdx
		rax = rcx + rcx * 2;            //lea rax, [rcx+rcx*2]
		rax <<= 0x2;            //shl rax, 0x02
		rcx = r8 * 0xE;                 //imul rcx, r8, 0x0E
		rcx -= rax;             //sub rcx, rax
		rax = driver::read<uint16_t>(rcx + r11 * 1 + 0x72C6420);                //movzx eax, word ptr [rcx+r11*1+0x72C6420]
		r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
		rax = r10;              //mov rax, r10
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rcx = r8;               //mov rcx, r8
		rax = r10;              //mov rax, r10
		rcx -= rdx;             //sub rcx, rdx
		rcx >>= 0x1;            //shr rcx, 0x01
		rcx += rdx;             //add rcx, rdx
		rcx >>= 0xC;            //shr rcx, 0x0C
		rcx = rcx * 0x1BC7;             //imul rcx, rcx, 0x1BC7
		r8 -= rcx;              //sub r8, rcx
		r9 = r8 * 0x1F84;               //imul r9, r8, 0x1F84
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0xC;            //shr rax, 0x0C
		rax = rax * 0x1BC7;             //imul rax, rax, 0x1BC7
		r9 -= rax;              //sub r9, rax
		rax = 0x4E5E0A72F0539783;               //mov rax, 0x4E5E0A72F0539783
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x6;            //shr rax, 0x06
		rcx = rax * 0x62;               //imul rcx, rax, 0x62
		rax = 0x3AEF6CA970586723;               //mov rax, 0x3AEF6CA970586723
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0x5;            //shr rdx, 0x05
		rcx += rdx;             //add rcx, rdx
		rax = rcx * 0x116;              //imul rax, rcx, 0x116
		rcx = r9 * 0x118;               //imul rcx, r9, 0x118
		rcx -= rax;             //sub rcx, rax
		r15 = driver::read<uint16_t>(rcx + r11 * 1 + 0x72CCF00);                //movsx r15d, word ptr [rcx+r11*1+0x72CCF00]
		return r15;
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
			return vis_base_ptr + 0x108;
	}
	return 0;
}