#include "decryption.h"
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb)->uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = readMemory<uintptr_t>(imageBase + 0x156D8DA8);
		if (!rbx)
			return rbx;
		rax = rbx;              //mov rax, rbx
		rax >>= 0x4;            //shr rax, 0x04
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0x8;            //shr rax, 0x08
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0x10;           //shr rax, 0x10
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0x20;           //shr rax, 0x20
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0xA;            //shr rax, 0x0A
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0x14;           //shr rax, 0x14
		rbx ^= rax;             //xor rbx, rax
		rcx = rbx;              //mov rcx, rbx
		rax = 0;                //and rax, 0xFFFFFFFFC0000000
		rcx >>= 0x28;           //shr rcx, 0x28
		rax = _rotl64(rax, 0x10);               //rol rax, 0x10
		rcx ^= rbx;             //xor rcx, rbx
		rax ^= readMemory<uintptr_t>(imageBase + 0x741C0F6);             //xor rax, [0x000000000529F0F0]
		rax = ~rax;             //not rax
		rcx *= readMemory<uintptr_t>(rax + 0x17);             //imul rcx, [rax+0x17]
		rax = rcx;              //mov rax, rcx
		rax >>= 0x14;           //shr rax, 0x14
		rcx ^= rax;             //xor rcx, rax
		rax = 0x7463DB0B2B177371;               //mov rax, 0x7463DB0B2B177371
		rbx = rcx;              //mov rbx, rcx
		rbx >>= 0x28;           //shr rbx, 0x28
		rbx ^= rcx;             //xor rbx, rcx
		rbx *= rax;             //imul rbx, rax
		rax = 0x5BA2C3D88A749719;               //mov rax, 0x5BA2C3D88A749719
		rbx += rax;             //add rbx, rax
		return rbx;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rax = readMemory<uintptr_t>(clientInfo + 0xae888);
		if (!rax)
			return rax;
		rbx = peb;              //mov rbx, gs:[rcx]
		rcx = rbx;              //mov rcx, rbx
		rcx >>= 0x13;           //shr rcx, 0x13
		rcx &= 0xF;
		switch (rcx) {
		case 0:
		{
			r14 = imageBase + 0x5681C16E;              //lea r14, [0x000000005469F0B3]
			r15 = imageBase + 0x3F5;           //lea r15, [0xFFFFFFFFFDE8332E]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529F006]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0x4646BEC261608187;               //mov rcx, 0x4646BEC261608187
			rax *= rcx;             //imul rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx *= r14;             //imul rcx, r14
			rax += rcx;             //add rax, rcx
			rcx = 0x65EB736D6D1DD6A5;               //mov rcx, 0x65EB736D6D1DD6A5
			rax *= rcx;             //imul rax, rcx
			rax += rbx;             //add rax, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rax ^= rcx;             //xor rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rdx ^= r15;             //xor rdx, r15
			rcx = 0x1DC1623A19814D39;               //mov rcx, 0x1DC1623A19814D39
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			return rax;
		}
		case 1:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529EAE8]
			rax += rbx;             //add rax, rbx
			rcx = 0x6AC4D77FDF341701;               //mov rcx, 0x6AC4D77FDF341701
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x11C981973C4E53AF;               //mov rcx, 0x11C981973C4E53AF
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= readMemory<uintptr_t>(rdx + 0xf);              //imul rax, [rdx+0x0F]
			return rax;
		}
		case 2:
		{
			rdx = imageBase + 0xC64E;          //lea rdx, [0xFFFFFFFFFDE8EC27]
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE825B8]
			r15 = imageBase + 0x24E5;          //lea r15, [0xFFFFFFFFFDE84A91]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529E683]
			rcx = 0xB15D7F738EEB1613;               //mov rcx, 0xB15D7F738EEB1613
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xB;            //shr rcx, 0x0B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx ^= rdx;             //xor rcx, rdx
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = r15;              //mov rcx, r15
			rcx -= rbx;             //sub rcx, rbx
			rax += rcx;             //add rax, rcx
			rcx = 0x595C1C57CDB69C5A;               //mov rcx, 0x595C1C57CDB69C5A
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xD;            //shr rcx, 0x0D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rax ^= rcx;             //xor rax, rcx
			rax += r11;             //add rax, r11
			return rax;
		}
		case 3:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE82026]
			r15 = imageBase + 0x33548939;              //lea r15, [0x00000000313CA953]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529E102]
			rax -= rbx;             //sub rax, rbx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x11;           //shr rcx, 0x11
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x22;           //shr rcx, 0x22
			rax ^= rcx;             //xor rax, rcx
			rdx = r11 + 0x533bfb86;                 //lea rdx, [r11+0x533BFB86]
			rdx += rbx;             //add rdx, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x23;           //shr rcx, 0x23
			rdx ^= rcx;             //xor rdx, rcx
			rcx = 0x230B81CC6FD851E1;               //mov rcx, 0x230B81CC6FD851E1
			rax ^= rdx;             //xor rax, rdx
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1D;           //shr rcx, 0x1D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3A;           //shr rcx, 0x3A
			rax ^= rcx;             //xor rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx *= r15;             //imul rcx, r15
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 4:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE81C09]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C12C);               //mov r9, [0x000000000529DCD8]
			rcx = 0xFFFFFFFFCF1F9161;               //mov rcx, 0xFFFFFFFFCF1F9161
			rcx -= r11;             //sub rcx, r11
			rax += rcx;             //add rax, rcx
			rax += r11;             //add rax, r11
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0x375E57E1F4BC5263;               //mov rcx, 0x375E57E1F4BC5263
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x3B1F54157FB3B915;               //mov rcx, 0x3B1F54157FB3B915
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x296F8FCDA4CD2FB;                //mov rcx, 0x296F8FCDA4CD2FB
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 5:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE8176B]
			r14 = imageBase + 0x242D59AB;              //lea r14, [0x000000002215710A]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C12C);               //mov r9, [0x000000000529D830]
			rcx = 0x20A3F7F917F2DB55;               //mov rcx, 0x20A3F7F917F2DB55
			rax *= rcx;             //imul rax, rcx
			rax += rbx;             //add rax, rbx
			rax ^= rbx;             //xor rax, rbx
			rax ^= r14;             //xor rax, r14
			rax ^= r11;             //xor rax, r11
			rcx = 0xCFE6C29C2D742C1F;               //mov rcx, 0xCFE6C29C2D742C1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x15;           //shr rcx, 0x15
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2A;           //shr rcx, 0x2A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x12;           //shr rcx, 0x12
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x24;           //shr rcx, 0x24
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 6:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE812A4]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529D3A9]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x27;           //shr rcx, 0x27
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x17;           //shr rcx, 0x17
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2E;           //shr rcx, 0x2E
			rax ^= rcx;             //xor rax, rcx
			rax ^= r11;             //xor rax, r11
			rcx = 0x632A2160D00CA41C;               //mov rcx, 0x632A2160D00CA41C
			rax ^= rcx;             //xor rax, rcx
			rcx = rbx;              //mov rcx, rbx
			uintptr_t RSP_0x68;
			RSP_0x68 = imageBase + 0x1C8BE99F;                 //lea rcx, [0x000000001A73FC65] : RSP+0x68
			rcx *= RSP_0x68;                //imul rcx, [rsp+0x68]
			rax += rcx;             //add rax, rcx
			rcx = 0xD37F1A1BB7236BFE;               //mov rcx, 0xD37F1A1BB7236BFE
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xE56A62B6F47C8A5B;               //mov rcx, 0xE56A62B6F47C8A5B
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 7:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE80E69]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529CF4C]
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rcx = rax;              //mov rcx, rax
			rdx ^= r10;             //xor rdx, r10
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rcx >>= 0x21;           //shr rcx, 0x21
			rax ^= rcx;             //xor rax, rcx
			rax *= readMemory<uintptr_t>(rdx + 0xf);              //imul rax, [rdx+0x0F]
			rax -= rbx;             //sub rax, rbx
			rax -= r11;             //sub rax, r11
			rax -= 0x3EC6A07E;              //sub rax, 0x3EC6A07E
			rcx = 0x3583A0E418F34F97;               //mov rcx, 0x3583A0E418F34F97
			rax -= rcx;             //sub rax, rcx
			rcx = 0x162D9980DDC815CE;               //mov rcx, 0x162D9980DDC815CE
			rax += rcx;             //add rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx -= r11;             //sub rcx, r11
			rcx -= 0x14B30F9D;              //sub rcx, 0x14B30F9D
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x1818DC09935BDADF;               //mov rcx, 0x1818DC09935BDADF
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 8:
		{
			r14 = imageBase + 0x4EA99E27;              //lea r14, [0x000000004C91A840]
			r15 = imageBase + 0x3E4B8CA2;              //lea r15, [0x000000003C3396AF]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529CB09]
			rdx = rbx;              //mov rdx, rbx
			rcx = rax;              //mov rcx, rax
			rdx *= r14;             //imul rdx, r14
			rax = 0x80FF2C9276E0583F;               //mov rax, 0x80FF2C9276E0583F
			rax *= rcx;             //imul rax, rcx
			rax += rdx;             //add rax, rdx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xD;            //shr rcx, 0x0D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rdx = rax;              //mov rdx, rax
			rdx >>= 0x34;           //shr rdx, 0x34
			rax ^= rdx;             //xor rax, rdx
			rcx = rbx;              //mov rcx, rbx
			rcx *= r15;             //imul rcx, r15
			rax -= rcx;             //sub rax, rcx
			rcx = 0x2ACB8A921B236E81;               //mov rcx, 0x2ACB8A921B236E81
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x26;           //shr rcx, 0x26
			rax ^= rcx;             //xor rax, rcx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= readMemory<uintptr_t>(rdx + 0xf);              //imul rax, [rdx+0x0F]
			rax += rbx;             //add rax, rbx
			return rax;
		}
		case 9:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529C6A2]
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE80563]
			r15 = imageBase + 0xC5F0;          //lea r15, [0xFFFFFFFFFDE8CB47]
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = imageBase + 0xB37C;          //lea rcx, [0xFFFFFFFFFDE8B60A]
			rdx += rcx;             //add rdx, rcx
			rcx = rax;              //mov rcx, rax
			rcx -= r11;             //sub rcx, r11
			rax = rdx;              //mov rax, rdx
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x94A35F9F56D93E3D;               //mov rcx, 0x94A35F9F56D93E3D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x19;           //shr rcx, 0x19
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x32;           //shr rcx, 0x32
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x7B7530197084FF42;               //mov rcx, 0x7B7530197084FF42
			rax += rcx;             //add rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rdx ^= r15;             //xor rdx, r15
			rcx = rax;              //mov rcx, rax
			rax = 0xC03FE5A75A6A0D6D;               //mov rax, 0xC03FE5A75A6A0D6D
			rax *= rcx;             //imul rax, rcx
			rax += rdx;             //add rax, rdx
			return rax;
		}
		case 10:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE8012C]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C12C);               //mov r9, [0x000000000529C217]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xFFFFFFFFFFFF327B;               //mov rcx, 0xFFFFFFFFFFFF327B
			rcx -= rbx;             //sub rcx, rbx
			rcx -= r11;             //sub rcx, r11
			rax += rcx;             //add rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1D;           //shr rcx, 0x1D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3A;           //shr rcx, 0x3A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rcx = readMemory<uintptr_t>(rcx + 0xf);               //mov rcx, [rcx+0x0F]
			uintptr_t RSP_0x68;
			RSP_0x68 = 0x27F7933E8BF8696D;          //mov rcx, 0x27F7933E8BF8696D : RSP+0x68
			rcx *= RSP_0x68;                //imul rcx, [rsp+0x68]
			rax *= rcx;             //imul rax, rcx
			rcx = 0x74C43827B5C654C5;               //mov rcx, 0x74C43827B5C654C5
			rax *= rcx;             //imul rax, rcx
			rcx = 0x94591F948A981ADB;               //mov rcx, 0x94591F948A981ADB
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 11:
		{
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE7FCB3]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C12C);               //mov r9, [0x000000000529BD58]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x15;           //shr rcx, 0x15
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2A;           //shr rcx, 0x2A
			rax ^= rcx;             //xor rax, rcx
			rcx = rbx;              //mov rcx, rbx
			rcx -= r11;             //sub rcx, r11
			rcx += 0xFFFFFFFFEA6D3C1C;              //add rcx, 0xFFFFFFFFEA6D3C1C
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rax += rbx;             //add rax, rbx
			rax ^= r11;             //xor rax, r11
			rcx = 0x59FA7C1FD43E49B5;               //mov rcx, 0x59FA7C1FD43E49B5
			rax *= rcx;             //imul rax, rcx
			rcx = 0x71B7F01FCA798C6C;               //mov rcx, 0x71B7F01FCA798C6C
			rax += rcx;             //add rax, rcx
			rcx = 0x7B36B30CDC8945D9;               //mov rcx, 0x7B36B30CDC8945D9
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 12:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529B86F]
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE7F730]
			rcx = r11 + 0xabb6;             //lea rcx, [r11+0xABB6]
			rcx += rbx;             //add rcx, rbx
			rax += rcx;             //add rax, rcx
			rdx = rbx;              //mov rdx, rbx
			rdx = ~rdx;             //not rdx
			rcx = imageBase + 0x7292648B;              //lea rcx, [0x00000000707A594B]
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			rax ^= r11;             //xor rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x23;           //shr rcx, 0x23
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x4D21D858D39DC567;               //mov rcx, 0x4D21D858D39DC567
			rax *= rcx;             //imul rax, rcx
			rcx = 0x60F85794A9567744;               //mov rcx, 0x60F85794A9567744
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 13:
		{
			r15 = imageBase + 0x1B8CFDF6;              //lea r15, [0x000000001974F08F]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529B356]
			rcx = rbx;              //mov rcx, rbx
			rcx ^= r15;             //xor rcx, r15
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2;            //shr rcx, 0x02
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x4;            //shr rcx, 0x04
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x8;            //shr rcx, 0x08
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x10;           //shr rcx, 0x10
			rax ^= rcx;             //xor rax, rcx
			rdx = rax;              //mov rdx, rax
			rcx = rbx;              //mov rcx, rbx
			rdx >>= 0x20;           //shr rdx, 0x20
			rcx = ~rcx;             //not rcx
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase + 0x7987;          //lea rax, [0xFFFFFFFFFDE86A65]
			rcx ^= rax;             //xor rcx, rax
			rax = rdx;              //mov rax, rdx
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2;            //shr rcx, 0x02
			rax ^= rcx;             //xor rax, rcx
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
			rcx = 0xAE130E4EC385BECF;               //mov rcx, 0xAE130E4EC385BECF
			rax *= rcx;             //imul rax, rcx
			rcx = 0x44A34D3274DE9D4C;               //mov rcx, 0x44A34D3274DE9D4C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x93B3CD52BD6CE705;               //mov rcx, 0x93B3CD52BD6CE705
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			return rax;
		}
		case 14:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529ADB1]
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
			rdx = imageBase + 0x6A7ADBB2;              //lea rdx, [0x000000006862C547]
			rdx = ~rdx;             //not rdx
			rcx = 0x7B3EF6263E4F5322;               //mov rcx, 0x7B3EF6263E4F5322
			//failed to translate: inc rdx
			rax ^= rcx;             //xor rax, rcx
			rax += rbx;             //add rax, rbx
			rax += rdx;             //add rax, rdx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= readMemory<uintptr_t>(rcx + 0xf);              //imul rax, [rcx+0x0F]
			rcx = 0xE6AE48778D3A97A5;               //mov rcx, 0xE6AE48778D3A97A5
			rax *= rcx;             //imul rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = 0x77FA0AD6AFC14C6E;               //mov rcx, 0x77FA0AD6AFC14C6E
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 15:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C12C);              //mov r10, [0x000000000529A817]
			r11 = imageBase;           //lea r11, [0xFFFFFFFFFDE7E6D8]
			r15 = imageBase + 0x22F46FE6;              //lea r15, [0x0000000020DC56B2]
			rax -= rbx;             //sub rax, rbx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = r15;              //mov rcx, r15
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rcx = ~rcx;             //not rcx
			rcx ^= rbx;             //xor rcx, rbx
			rdx ^= r10;             //xor rdx, r10
			rax += rcx;             //add rax, rcx
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rax *= readMemory<uintptr_t>(rdx + 0xf);              //imul rax, [rdx+0x0F]
			rcx = 0x89F2FB8B64D2BB21;               //mov rcx, 0x89F2FB8B64D2BB21
			rax *= rcx;             //imul rax, rcx
			rcx = 0x12087E33D51641D6;               //mov rcx, 0x12087E33D51641D6
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rax += r11;             //add rax, r11
			return rax;
		}
		}
	}
	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb)->uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rdx = readMemory<uintptr_t>(imageBase + 0x131706E8);
		if (!rdx)
			return rdx;
		r11 = peb;              //mov r11, gs:[rax]
		rax = r11;              //mov rax, r11
		rax = _rotl64(rax, 0x2C);               //rol rax, 0x2C
		rax &= 0xF;
		switch (rax) {
		case 0:
		{
			r15 = imageBase + 0x4E8CD5CA;              //lea r15, [0x000000004C3762AC]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC4EB5]
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rax += r11;             //add rax, r11
			rax ^= r11;             //xor rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			rax = 0x553ACCEE19BBCF36;               //mov rax, 0x553ACCEE19BBCF36
			rdx += rax;             //add rdx, rax
			rax = imageBase + 0x69B4F9DF;              //lea rax, [0x00000000675F83CD]
			rax = ~rax;             //not rax
			rax += r11;             //add rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = 0x252FA0387E58DE09;               //mov rax, 0x252FA0387E58DE09
			rdx *= rax;             //imul rdx, rax
			rax = 0x65420ED4B33B078E;               //mov rax, 0x65420ED4B33B078E
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 1:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA8849]
			r12 = imageBase + 0x32BDFE70;              //lea r12, [0x00000000306886AD]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C21F);               //mov r9, [0x0000000004EC49E1]
			rax = 0x2738F5D08B35534A;               //mov rax, 0x2738F5D08B35534A
			rdx -= rax;             //sub rdx, rax
			rdx ^= rbx;             //xor rdx, rbx
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rax = 0x4DE6A8625159EF5B;               //mov rax, 0x4DE6A8625159EF5B
			rdx *= rax;             //imul rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = 0x7021C6534DEED3A7;               //mov rax, 0x7021C6534DEED3A7
			rdx -= rax;             //sub rdx, rax
			rax = r11;              //mov rax, r11
			rax -= rbx;             //sub rax, rbx
			rax += 0xFFFFFFFF8B99FD07;              //add rax, 0xFFFFFFFF8B99FD07
			rdx += rax;             //add rdx, rax
			rax = r12;              //mov rax, r12
			rax -= r11;             //sub rax, r11
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 2:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA8288]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C21F);               //mov r9, [0x0000000004EC4454]
			rdx += r11;             //add rdx, r11
			rdx ^= r11;             //xor rdx, r11
			rax = 0xAB89D371DD740BA3;               //mov rax, 0xAB89D371DD740BA3
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = 0x7A2ECE506702FE72;               //mov rax, 0x7A2ECE506702FE72
			rdx += rax;             //add rdx, rax
			rdx ^= rbx;             //xor rdx, rbx
			rax = 0x259C5F1D0D3FCB0D;               //mov rax, 0x259C5F1D0D3FCB0D
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			return rdx;
		}
		case 3:
		{
			//failed to translate: pop rdx
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA7E43]
			r13 = imageBase + 0x5C466626;              //lea r13, [0x0000000059F0E45D]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC4016]
			rax = r11;              //mov rax, r11
			rax ^= r13;             //xor rax, r13
			rdx += rax;             //add rdx, rax
			rax = imageBase + 0xEE8E;          //lea rax, [0xFFFFFFFFFDAB6972]
			rcx = r11;              //mov rcx, r11
			rax = ~rax;             //not rax
			rcx = ~rcx;             //not rcx
			rcx *= rax;             //imul rcx, rax
			rax = 0x7ADB0FD286D0145;                //mov rax, 0x7ADB0FD286D0145
			rdx ^= rcx;             //xor rdx, rcx
			rdx ^= rax;             //xor rdx, rax
			rdx += rbx;             //add rdx, rbx
			rax = 0x58FB8C3CFB3EE0F1;               //mov rax, 0x58FB8C3CFB3EE0F1
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rdx += r11;             //add rdx, r11
			return rdx;
		}
		case 4:
		{
			r14 = imageBase + 0xD3D8;          //lea r14, [0xFFFFFFFFFDAB4DE2]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C21F);               //mov r9, [0x0000000004EC3BC2]
			rax = 0x25127D22679BF12;                //mov rax, 0x25127D22679BF12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1;            //shr rax, 0x01
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2;            //shr rax, 0x02
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0xECF979C74E912F9;                //mov rax, 0xECF979C74E912F9
			rdx += rax;             //add rdx, rax
			rdx -= r11;             //sub rdx, r11
			rax = r14;              //mov rax, r14
			rax = ~rax;             //not rax
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			rax = readMemory<uintptr_t>(rax + 0x13);              //mov rax, [rax+0x13]
			uintptr_t RSP_0x48;
			RSP_0x48 = 0xDC181F18E9BA64BD;          //mov rax, 0xDC181F18E9BA64BD : RSP+0x48
			rax *= RSP_0x48;                //imul rax, [rsp+0x48]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xB;            //shr rax, 0x0B
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x16;           //shr rax, 0x16
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2C;           //shr rax, 0x2C
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 5:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC36E6]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA74B4]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax >>= 0x20;           //shr rax, 0x20
			rax ^= rdx;             //xor rax, rdx
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x13);             //imul rax, [rcx+0x13]
			rdx = rax;              //mov rdx, rax
			rdx >>= 0x22;           //shr rdx, 0x22
			rdx ^= rax;             //xor rdx, rax
			rdx ^= rbx;             //xor rdx, rbx
			rax = 0xCFC784CB0ACCB497;               //mov rax, 0xCFC784CB0ACCB497
			rdx *= rax;             //imul rdx, rax
			rax = 0x48B410E46DDECD3D;               //mov rax, 0x48B410E46DDECD3D
			rdx -= rax;             //sub rdx, rax
			rax = 0x54AB2821D5A5B1D3;               //mov rax, 0x54AB2821D5A5B1D3
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xD;            //shr rax, 0x0D
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 6:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA6F9D]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC3198]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = r11;              //mov rax, r11
			rax -= rbx;             //sub rax, rbx
			rax += 0xFFFFFFFFFFFF98A3;              //add rax, 0xFFFFFFFFFFFF98A3
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x4;            //shr rax, 0x04
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0x6B6087AE3E22EE1D;               //mov rax, 0x6B6087AE3E22EE1D
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3C;           //shr rax, 0x3C
			rdx ^= rax;             //xor rdx, rax
			rax = 0x1DE794DED5CE214D;               //mov rax, 0x1DE794DED5CE214D
			rdx *= rax;             //imul rdx, rax
			rdx ^= rbx;             //xor rdx, rbx
			rax = 0x4BF164FBD0D0B8B6;               //mov rax, 0x4BF164FBD0D0B8B6
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 7:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC2D05]
			r15 = imageBase + 0x2959CF17;              //lea r15, [0x00000000270439EA]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = 0xEAB78396DC97F3BC;               //mov rax, 0xEAB78396DC97F3BC
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xF;            //shr rax, 0x0F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3C;           //shr rax, 0x3C
			rdx ^= rax;             //xor rdx, rax
			rax = 0x66E14A0352D5C823;               //mov rax, 0x66E14A0352D5C823
			rdx *= rax;             //imul rdx, rax
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1B;           //shr rax, 0x1B
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x36;           //shr rax, 0x36
			rdx ^= rax;             //xor rdx, rax
			rax = 0x11B611FA962F631E;               //mov rax, 0x11B611FA962F631E
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 8:
		{
			//failed to translate: pop rdx
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA65F6]
			r15 = imageBase + 0xED59;          //lea r15, [0xFFFFFFFFFDAB5343]
			r9 = readMemory<uintptr_t>(imageBase + 0x741C21F);               //mov r9, [0x0000000004EC27CF]
			rax = 0x5C5DFE4AC3740E32;               //mov rax, 0x5C5DFE4AC3740E32
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rdx += rbx;             //add rdx, rbx
			rax = 0xB5D7BA8B364E68DE;               //mov rax, 0xB5D7BA8B364E68DE
			rdx ^= rax;             //xor rdx, rax
			rax = 0x69C8838FFC9F4749;               //mov rax, 0x69C8838FFC9F4749
			rdx *= rax;             //imul rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax ^= r15;             //xor rax, r15
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 9:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC23B3]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA617C]
			r15 = imageBase + 0x364F6B8E;              //lea r15, [0x0000000033F9CCFE]
			rdx += r11;             //add rdx, r11
			rax = 0x8BE137A04B9268A0;               //mov rax, 0x8BE137A04B9268A0
			rdx ^= rax;             //xor rdx, rax
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rdx += rax;             //add rdx, rax
			rdx -= rbx;             //sub rdx, rbx
			rdx -= 0x9198;          //sub rdx, 0x9198
			rcx = r11 + 0x1;                //lea rcx, [r11+0x01]
			rax = rdx;              //mov rax, rdx
			rcx *= r15;             //imul rcx, r15
			rdx = 0xF421CB3564828570;               //mov rdx, 0xF421CB3564828570
			rdx ^= rax;             //xor rdx, rax
			rdx += rcx;             //add rdx, rcx
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rax = readMemory<uintptr_t>(rax + 0x13);              //mov rax, [rax+0x13]
			uintptr_t RSP_0x30;
			RSP_0x30 = 0xE303C390E44C643;           //mov rax, 0xE303C390E44C643 : RSP+0x30
			rax *= RSP_0x30;                //imul rax, [rsp+0x30]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 10:
		{
			r14 = imageBase + 0x2185;          //lea r14, [0xFFFFFFFFFDAA7E4C]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC1EBE]
			rax = 0x15A9C311301361F2;               //mov rax, 0x15A9C311301361F2
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xD;            //shr rax, 0x0D
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1A;           //shr rax, 0x1A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x34;           //shr rax, 0x34
			rdx ^= rax;             //xor rdx, rax
			rax = 0x54B311C3AD6B0511;               //mov rax, 0x54B311C3AD6B0511
			rdx *= rax;             //imul rdx, rax
			rax = 0x43054BA259457665;               //mov rax, 0x43054BA259457665
			rdx *= rax;             //imul rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = r14;              //mov rax, r14
			rax = ~rax;             //not rax
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = imageBase + 0xF3BB;          //lea rax, [0xFFFFFFFFFDAB4E0F]
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 11:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC1AF2]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA58C0]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = imageBase + 0x7D137684;              //lea rax, [0x000000007ABDCBF5]
			rax -= r11;             //sub rax, r11
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rax = 0x2A8725B0D2B802A1;               //mov rax, 0x2A8725B0D2B802A1
			rdx -= rax;             //sub rdx, rax
			rcx = r11 + rbx * 1;            //lea rcx, [r11+rbx*1]
			rax = 0xC15CB927704409C8;               //mov rax, 0xC15CB927704409C8
			rdx += rax;             //add rdx, rax
			rdx += rcx;             //add rdx, rcx
			rdx += rbx;             //add rdx, rbx
			rax = 0x94FE6093A61701ED;               //mov rax, 0x94FE6093A61701ED
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 12:
		{
			//failed to translate: pop rdx
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC168C]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDAA545A]
			r13 = imageBase + 0x60ECE0D0;              //lea r13, [0x000000005E97351E]
			rcx = r11 + rbx * 1;            //lea rcx, [r11+rbx*1]
			rax = 0xC2D6A1583C735B2E;               //mov rax, 0xC2D6A1583C735B2E
			rax += rdx;             //add rax, rdx
			rdx = rax + rcx * 2;            //lea rdx, [rax+rcx*2]
			rax = r13;              //mov rax, r13
			rax = ~rax;             //not rax
			//failed to translate: inc rax
			rax += r11;             //add rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = 0xE20934E3E86938FD;               //mov rax, 0xE20934E3E86938FD
			rdx ^= rax;             //xor rdx, rax
			rax = 0xE5168384FA42C77F;               //mov rax, 0xE5168384FA42C77F
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x15;           //shr rax, 0x15
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2A;           //shr rax, 0x2A
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			return rdx;
		}
		case 13:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC11C3]
			rbx = imageBase + 0x6F70331B;              //lea rbx, [0x000000006D1A82B1]
			rax = imageBase + 0xCC13;          //lea rax, [0xFFFFFFFFFDAB1948]
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = 0x22748A1523D65125;               //mov rax, 0x22748A1523D65125
			rdx *= rax;             //imul rdx, rax
			rdx -= r11;             //sub rdx, r11
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax += rbx;             //add rax, rbx
			rdx ^= rax;             //xor rdx, rax
			rax = 0x69C1C80D57D94665;               //mov rax, 0x69C1C80D57D94665
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0x94C7E91E27E02F0E;               //mov rax, 0x94C7E91E27E02F0E
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 14:
		{
			r9 = readMemory<uintptr_t>(imageBase + 0x741C21F);               //mov r9, [0x0000000004EC0D14]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = ~rax;             //not rax
			rdx *= readMemory<uintptr_t>(rax + 0x13);             //imul rdx, [rax+0x13]
			rax = 0x31ADB3FED6FCCB21;               //mov rax, 0x31ADB3FED6FCCB21
			rdx += rax;             //add rdx, rax
			rax = 0x44335EB919CDD541;               //mov rax, 0x44335EB919CDD541
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x9;            //shr rax, 0x09
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = 0x1B1A73B7C628B9E7;               //mov rax, 0x1B1A73B7C628B9E7
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 15:
		{
			//failed to translate: pop rdx
			r15 = imageBase + 0xA25;           //lea r15, [0xFFFFFFFFFDAA4EF0]
			r12 = imageBase + 0xBDCD;          //lea r12, [0xFFFFFFFFFDAB028C]
			r13 = imageBase + 0x6821EE51;              //lea r13, [0x0000000065CC3304]
			r10 = readMemory<uintptr_t>(imageBase + 0x741C21F);              //mov r10, [0x0000000004EC067F]
			rax = r12;              //mov rax, r12
			rax *= r11;             //imul rax, r11
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xF;            //shr rax, 0x0F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3C;           //shr rax, 0x3C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xE;            //shr rax, 0x0E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = rdx;              //mov rax, rdx
			rcx ^= r10;             //xor rcx, r10
			rax >>= 0x38;           //shr rax, 0x38
			rcx = ~rcx;             //not rcx
			rdx ^= rax;             //xor rdx, rax
			rdx *= readMemory<uintptr_t>(rcx + 0x13);             //imul rdx, [rcx+0x13]
			rcx = imageBase + 0x874F;          //lea rcx, [0xFFFFFFFFFDAAC751]
			rax = 0xEBAE8BCAD08BC7A3;               //mov rax, 0xEBAE8BCAD08BC7A3
			rdx *= rax;             //imul rdx, rax
			rax = r13;              //mov rax, r13
			rax ^= r11;             //xor rax, r11
			rdx += rax;             //add rdx, rax
			rax = r15;              //mov rax, r15
			rax *= r11;             //imul rax, r11
			rdx -= rax;             //sub rdx, rax
			rax = r11 + rcx * 1;            //lea rax, [r11+rcx*1]
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		}
	}
	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase)->uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = index;
		rcx = rbx * 0x13C8;
		rax = 0xAD00F8B1657F01E7;               //mov rax, 0xAD00F8B1657F01E7
		rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDE95C5D]
		rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
		r10 = 0xA46E5102D9A9877D;               //mov r10, 0xA46E5102D9A9877D
		rdx >>= 0xC;            //shr rdx, 0x0C
		rax = rdx * 0x17AD;             //imul rax, rdx, 0x17AD
		rcx -= rax;             //sub rcx, rax
		rax = 0xA08DBD20F71A2515;               //mov rax, 0xA08DBD20F71A2515
		r9 = rcx * 0x17AD;              //imul r9, rcx, 0x17AD
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0xC;            //shr rdx, 0x0C
		rax = rdx * 0x1983;             //imul rax, rdx, 0x1983
		r9 -= rax;              //sub r9, rax
		rax = 0xE38E38E38E38E38F;               //mov rax, 0xE38E38E38E38E38F
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rcx = r9;               //mov rcx, r9
		rdx >>= 0xB;            //shr rdx, 0x0B
		rax = rdx * 0x780;              //imul rax, rdx, 0x780
		rcx -= rax;             //sub rcx, rax
		rax = 0xCCCCCCCCCCCCCCCD;               //mov rax, 0xCCCCCCCCCCCCCCCD
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		r8 = rcx + rcx * 2;             //lea r8, [rcx+rcx*2]
		rdx >>= 0x2;            //shr rdx, 0x02
		r8 <<= 0x2;             //shl r8, 0x02
		rax = rdx + rdx * 4;            //lea rax, [rdx+rdx*4]
		rax += rax;             //add rax, rax
		r8 -= rax;              //sub r8, rax
		rax = readMemory<uint16_t>(r8 + rbx * 1 + 0x74358D0);                 //movzx eax, word ptr [r8+rbx*1+0x74358D0]
		r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
		rax = r10;              //mov rax, r10
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r10;              //mov rax, r10
		rdx >>= 0xC;            //shr rdx, 0x0C
		rcx = rdx * 0x18E9;             //imul rcx, rdx, 0x18E9
		r8 -= rcx;              //sub r8, rcx
		r9 = r8 * 0x22C9;               //imul r9, r8, 0x22C9
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0xC;            //shr rdx, 0x0C
		rax = rdx * 0x18E9;             //imul rax, rdx, 0x18E9
		r9 -= rax;              //sub r9, rax
		rax = 0x8888888888888889;               //mov rax, 0x8888888888888889
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = 0x27DFA38A1CE4D6F9;               //mov rax, 0x27DFA38A1CE4D6F9
		rdx >>= 0x3;            //shr rdx, 0x03
		rcx = rdx * 0xF;                //imul rcx, rdx, 0x0F
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x8;            //shr rax, 0x08
		rcx += rax;             //add rcx, rax
		rax = rcx * 0x376;              //imul rax, rcx, 0x376
		rcx = r9 * 0x378;               //imul rcx, r9, 0x378
		rcx -= rax;             //sub rcx, rax
		rsi = readMemory<uint16_t>(rcx + rbx * 1 + 0x743B2D0);                //movsx esi, word ptr [rcx+rbx*1+0x743B2D0]
		return rsi;
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