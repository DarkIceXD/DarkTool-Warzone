#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = driver::read<uintptr_t>(imageBase + 0x1F0D3938);
		if (!rbx)
			return rbx;
		r8 = peb;               //mov r8, gs:[rax]
		r9 = imageBase;    rdx = 0x22CBFA5C133D766B;               //mov rdx, 0x22CBFA5C133D766B
		rax = rbx;              //mov rax, rbx
		rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
		rax >>= 0x25;           //shr rax, 0x25
		rbx ^= rax;             //xor rbx, rax
		rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
		rcx ^= driver::read<uintptr_t>(imageBase + 0x78210EC);             //xor rcx, [0x0000000005045739]
		rax = 0x2C925E0599A4412F;               //mov rax, 0x2C925E0599A4412F
		rbx *= rdx;             //imul rbx, rdx
		rcx = ~rcx;             //not rcx
		rbx += rax;             //add rbx, rax
		rbx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rbx, [rcx+0x09]
		rbx -= r8;              //sub rbx, r8
		rbx += r9;              //add rbx, r9
		return rbx;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rax = driver::read<uintptr_t>(clientInfo + 0xa2c08);
		if (!rax)
			return rax;
		r11 = peb;              //mov r11, gs:[rcx]
		rcx = r11;              //mov rcx, r11
		rcx >>= 0xD;            //shr rcx, 0x0D
		rcx &= 0xF;
		switch (rcx) {
		case 0:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x00000000050456EE]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x9E38BF624AD3140F;               //mov rcx, 0x9E38BF624AD3140F
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8240E2]
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
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x755FBB47AE09AD86;               //mov rcx, 0x755FBB47AE09AD86
			rax += rcx;             //add rax, rcx
			rax += r11;             //add rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x15;           //shr rcx, 0x15
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2A;           //shr rcx, 0x2A
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 1:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x00000000050450D5]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = 0x7E1C80D166226A23;               //mov rcx, 0x7E1C80D166226A23
			rax *= rcx;             //imul rax, rcx
			rcx = 0x4A28F073A6F03584;               //mov rcx, 0x4A28F073A6F03584
			rax -= rcx;             //sub rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD823DFB]
			rax += rcx;             //add rax, rcx
			rcx = 0x7C93633C19F8E759;               //mov rcx, 0x7C93633C19F8E759
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD823F49]
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x26;           //shr rcx, 0x26
			rax ^= rcx;             //xor rax, rcx
			rax -= r11;             //sub rax, r11
			return rax;
		}
		case 2:
		{
			rsi = imageBase + 0x39BD99F1;              //lea rsi, [0x00000000373FD631]
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x0000000005044CF5]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = r11;              //mov rcx, r11
			rcx *= rsi;             //imul rcx, rsi
			rax -= rcx;             //sub rax, rcx
			rcx = 0x3AA9562CB5774ADE;               //mov rcx, 0x3AA9562CB5774ADE
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xA;            //shr rcx, 0x0A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rax += r11;             //add rax, r11
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8238CA]
			rax -= rcx;             //sub rax, rcx
			rcx = 0x78F02B7AD6A222C1;               //mov rcx, 0x78F02B7AD6A222C1
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 3:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x000000000504479B]
			rcx = 0x752B1E6822441F99;               //mov rcx, 0x752B1E6822441F99
			rax ^= rcx;             //xor rax, rcx
			rdx = r11;              //mov rdx, r11
			rdx = ~rdx;             //not rdx
			rcx = imageBase + 0x2C4B;          //lea rcx, [0xFFFFFFFFFD825F4C]
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			r14 = 0xEC1FD435349004E7;               //mov r14, 0xEC1FD435349004E7
			rax += r14;             //add rax, r14
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xC907060823DB336F;               //mov rcx, 0xC907060823DB336F
			rax *= rcx;             //imul rax, rcx
			rax += r11;             //add rax, r11
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 4:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x00000000050442F6]
			r14 = imageBase + 0x7967;          //lea r14, [0xFFFFFFFFFD82AB1C]
			rcx = r11;              //mov rcx, r11
			rcx ^= r14;             //xor rcx, r14
			rcx += r11;             //add rcx, r11
			rax -= rcx;             //sub rax, rcx
			rcx = imageBase + 0x1D7;           //lea rcx, [0xFFFFFFFFFD82301C]
			rcx -= r11;             //sub rcx, r11
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x80FEAE873EA35F31;               //mov rcx, 0x80FEAE873EA35F31
			rax *= rcx;             //imul rax, rcx
			rcx = 0x5946C1C563FF5DB5;               //mov rcx, 0x5946C1C563FF5DB5
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rax ^= rcx;             //xor rax, rcx
			rsi = 0xA758813978033BF2;               //mov rsi, 0xA758813978033BF2
			rax += rsi;             //add rax, rsi
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			return rax;
		}
		case 5:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x0000000005043DD0]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8227CF]
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1F;           //shr rcx, 0x1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3E;           //shr rcx, 0x3E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xD;            //shr rcx, 0x0D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x17B6DB8315AA1B89;               //mov rcx, 0x17B6DB8315AA1B89
			rax *= rcx;             //imul rax, rcx
			rcx = 0x3E4B475BF8EA16F3;               //mov rcx, 0x3E4B475BF8EA16F3
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD822BD5]
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x30BC3D77CD84EFEF;               //mov rcx, 0x30BC3D77CD84EFEF
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 6:
		{
			r15 = imageBase + 0x9276;          //lea r15, [0xFFFFFFFFFD82B9F7]
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x0000000005043837]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x25;           //shr rcx, 0x25
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xF;            //shr rcx, 0x0F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x737EA267D6DD56C2;               //mov rcx, 0x737EA267D6DD56C2
			rax += rcx;             //add rax, rcx
			rax -= r11;             //sub rax, r11
			rdx = r11;              //mov rdx, r11
			rdx = ~rdx;             //not rdx
			rax += r15;             //add rax, r15
			rax += rdx;             //add rax, rdx
			rcx = 0x9BA8C81C5AF1FBD5;               //mov rcx, 0x9BA8C81C5AF1FBD5
			rax *= rcx;             //imul rax, rcx
			rcx = 0x436D06370BF36C94;               //mov rcx, 0x436D06370BF36C94
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 7:
		{
			r14 = imageBase + 0x435A;          //lea r14, [0xFFFFFFFFFD8265ED]
			r15 = imageBase + 0x723E23F4;              //lea r15, [0x000000006FC0467B]
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x000000000504335F]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rdx = rax;              //mov rdx, rax
			rdx >>= 0x36;           //shr rdx, 0x36
			rax ^= rdx;             //xor rax, rdx
			rcx = r11;              //mov rcx, r11
			rcx ^= r15;             //xor rcx, r15
			rax -= rcx;             //sub rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = 0xC778B8D2E2ADB7B9;               //mov rcx, 0xC778B8D2E2ADB7B9
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x50C73C28CF860E6D;               //mov rcx, 0x50C73C28CF860E6D
			rax *= rcx;             //imul rax, rcx
			rcx = 0x1E24A17857596D18;               //mov rcx, 0x1E24A17857596D18
			rax -= rcx;             //sub rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx *= r14;             //imul rcx, r14
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 8:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x0000000005042F4F]
			r15 = imageBase + 0x12865D13;              //lea r15, [0x0000000010087B21]
			rcx = r15;              //mov rcx, r15
			rcx = ~rcx;             //not rcx
			rcx ^= r11;             //xor rcx, r11
			rax += rcx;             //add rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = r11;              //mov rcx, r11
			rcx -= imageBase;          //sub rcx, [rbp-0x70] -- didn't find trace -> use base
			rcx -= 0x8C41;          //sub rcx, 0x8C41
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xB;            //shr rcx, 0x0B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x16;           //shr rcx, 0x16
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2C;           //shr rcx, 0x2C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x1E65D2E7F53D0599;               //mov rcx, 0x1E65D2E7F53D0599
			rax *= rcx;             //imul rax, rcx
			rcx = imageBase + 0x1BE4CBEF;              //lea rcx, [0x000000001966E661]
			rdx = 0x1;              //mov edx, 0x01
			rdx -= rcx;             //sub rdx, rcx
			rcx = imageBase + 0x676F5BD7;              //lea rcx, [0x0000000064F17632]
			rcx = ~rcx;             //not rcx
			rcx += rax;             //add rcx, rax
			rax = 0x7D1A798F4028AA98;               //mov rax, 0x7D1A798F4028AA98
			rax += rcx;             //add rax, rcx
			rdx *= r11;             //imul rdx, r11
			rax += rdx;             //add rax, rdx
			return rax;
		}
		case 9:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x0000000005042A15]
			rax -= r11;             //sub rax, r11
			rax += 0xC6D1;          //add rax, 0xC6D1
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8216F0]
			rax -= rcx;             //sub rax, rcx
			rcx = 0xBA48EB7B0323A268;               //mov rcx, 0xBA48EB7B0323A268
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x144E79F8DA45C107;               //mov rcx, 0x144E79F8DA45C107
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 10:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x782112E);               //mov r9, [0x00000000050425C6]
			rcx = 0x6A3E839949A7CB7F;               //mov rcx, 0x6A3E839949A7CB7F
			rax *= rcx;             //imul rax, rcx
			rcx = 0x286F0DFA3863B725;               //mov rcx, 0x286F0DFA3863B725
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x6;            //shr rcx, 0x06
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xC;            //shr rcx, 0x0C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x30;           //shr rcx, 0x30
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD82115B]
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x45E8866AB8385AB3;               //mov rcx, 0x45E8866AB8385AB3
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xE;            //shr rcx, 0x0E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1C;           //shr rcx, 0x1C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x38;           //shr rcx, 0x38
			rax ^= rcx;             //xor rax, rcx
			rax -= r11;             //sub rax, r11
			return rax;
		}
		case 11:
		{
			r15 = imageBase + 0x6FB85EAB;              //lea r15, [0x000000006D3A6EE9]
			rdx = imageBase + 0x8104;          //lea rdx, [0xFFFFFFFFFD829136]
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x0000000005042106]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = r11;              //mov rcx, r11
			rcx *= rdx;             //imul rcx, rdx
			rax -= rcx;             //sub rax, rcx
			rcx = 0x9F8D511DDCFF7CF9;               //mov rcx, 0x9F8D511DDCFF7CF9
			rax *= rcx;             //imul rax, rcx
			rcx = r15;              //mov rcx, r15
			rcx = ~rcx;             //not rcx
			rcx += r11;             //add rcx, r11
			rax += rcx;             //add rax, rcx
			rcx = r11;              //mov rcx, r11
			uintptr_t RSP_0xFFFFFFFFFFFFFF90;
			RSP_0xFFFFFFFFFFFFFF90 = imageBase + 0xD4E1;               //lea rcx, [0xFFFFFFFFFD82E534] : RBP+0xFFFFFFFFFFFFFF90
			rcx *= RSP_0xFFFFFFFFFFFFFF90;          //imul rcx, [rbp-0x70]
			rax ^= rcx;             //xor rax, rcx
			rdx = r11;              //mov rdx, r11
			rcx = imageBase + 0xD525;          //lea rcx, [0xFFFFFFFFFD82E26B]
			rdx *= rcx;             //imul rdx, rcx
			rcx = 0xA6843FD12094A545;               //mov rcx, 0xA6843FD12094A545
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			return rax;
		}
		case 12:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x0000000005041C16]
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD820A22]
			rax -= rcx;             //sub rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rax ^= r11;             //xor rax, r11
			rcx = 0xD313F71358156A05;               //mov rcx, 0xD313F71358156A05
			rax += rcx;             //add rax, rcx
			rcx = 0xE12B8F402CAE2E43;               //mov rcx, 0xE12B8F402CAE2E43
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x53DD4F0F31203213;               //mov rcx, 0x53DD4F0F31203213
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x12;           //shr rcx, 0x12
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x24;           //shr rcx, 0x24
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 13:
		{
			r14 = imageBase + 0x42489571;              //lea r14, [0x000000003FCA9D13]
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x000000000504186B]
			rdx = r11;              //mov rdx, r11
			rdx = ~rdx;             //not rdx
			rcx = r14;              //mov rcx, r14
			rcx = ~rcx;             //not rcx
			rax += rcx;             //add rax, rcx
			rax += rdx;             //add rax, rdx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8206A9]
			rax -= rcx;             //sub rax, rcx
			rcx = imageBase;           //lea rcx, [0xFFFFFFFFFD8202D0]
			rax -= rcx;             //sub rax, rcx
			rcx = 0x9058D51FC87FE52F;               //mov rcx, 0x9058D51FC87FE52F
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x21;           //shr rcx, 0x21
			rax ^= rcx;             //xor rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx -= imageBase;          //sub rcx, [rbp-0x70] -- didn't find trace -> use base
			rcx += 0xFFFFFFFF891A3C8C;              //add rcx, 0xFFFFFFFF891A3C8C
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x6;            //shr rcx, 0x06
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xC;            //shr rcx, 0x0C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rcx = rax;              //mov rcx, rax
			rdx = _byteswap_uint64(rdx);            //bswap rdx
			rcx >>= 0x30;           //shr rcx, 0x30
			rax ^= rcx;             //xor rax, rcx
			rax *= driver::read<uintptr_t>(rdx + 0x7);              //imul rax, [rdx+0x07]
			return rax;
		}
		case 14:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x000000000504137B]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x26;           //shr rcx, 0x26
			rax ^= rcx;             //xor rax, rcx
			rax -= r11;             //sub rax, r11
			rcx = 0x1E0565F71BE1E433;               //mov rcx, 0x1E0565F71BE1E433
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = 0x74FF870987896E;                 //mov rcx, 0x74FF870987896E
			rax -= rcx;             //sub rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xA;            //shr rcx, 0x0A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x17;           //shr rcx, 0x17
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x2E;           //shr rcx, 0x2E
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x61CE29C21FA16684;               //mov rcx, 0x61CE29C21FA16684
			rax += rcx;             //add rax, rcx
			return rax;
		}
		case 15:
		{
			r15 = imageBase + 0x4B1B9B48;              //lea r15, [0x00000000489D9844]
			r10 = driver::read<uintptr_t>(imageBase + 0x782112E);              //mov r10, [0x0000000005040DA1]
			rcx = r15;              //mov rcx, r15
			rcx = ~rcx;             //not rcx
			rcx ^= r11;             //xor rcx, r11
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x25;           //shr rcx, 0x25
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3;            //shr rcx, 0x03
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x6;            //shr rcx, 0x06
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xC;            //shr rcx, 0x0C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x30;           //shr rcx, 0x30
			rax ^= rcx;             //xor rax, rcx
			rax ^= driver::read<uintptr_t>(imageBase + 0x27E0587);             //xor rax, [rbp-0x70] -- didn't find trace -> use base
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rax *= driver::read<uintptr_t>(rcx + 0x7);              //imul rax, [rcx+0x07]
			rcx = 0x76A71F3008631679;               //mov rcx, 0x76A71F3008631679
			rax *= rcx;             //imul rax, rcx
			rcx = 0x2542281AF0A8CEC9;               //mov rcx, 0x2542281AF0A8CEC9
			rax += rcx;             //add rax, rcx
			return rax;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rdx = driver::read<uintptr_t>(imageBase + 0x1C262B48);
		if (!rdx)
			return rdx;
		r11 = peb;              //mov r11, gs:[rax]
		rax = r11;              //mov rax, r11
		rax = _rotr64(rax, 0x19);               //ror rax, 0x19
		rax &= 0xF;
		switch (rax) {
		case 0:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x7821223);               //mov r9, [0x0000000004CA9601]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD488269]
			rdx += rax;             //add rdx, rax
			rax = 0x9D49503AEEC3085C;               //mov rax, 0x9D49503AEEC3085C
			rdx ^= rax;             //xor rdx, rax
			r15 = imageBase;           //lea r15, [0xFFFFFFFFFD48807B]
			rdx += r15;             //add rdx, r15
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = 0x5F5A112DC99B7A4B;               //mov rax, 0x5F5A112DC99B7A4B
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD48838E]
			rdx += rax;             //add rdx, rax
			rax = 0x913CFC69B7F3F340;               //mov rax, 0x913CFC69B7F3F340
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xC;            //shr rax, 0x0C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x18;           //shr rax, 0x18
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x30;           //shr rax, 0x30
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 1:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA918F]
			rdx ^= r11;             //xor rdx, r11
			rax = 0x56F3C62967B05B8A;               //mov rax, 0x56F3C62967B05B8A
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rdx ^= rax;             //xor rdx, rax
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rdx, [rcx+0x09]
			rax = rdx;              //mov rax, rdx
			rax >>= 0xB;            //shr rax, 0x0B
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x16;           //shr rax, 0x16
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2C;           //shr rax, 0x2C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x7;            //shr rax, 0x07
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xE;            //shr rax, 0x0E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rdx ^= rax;             //xor rdx, rax
			rax = 0xA7692940131CCC49;               //mov rax, 0xA7692940131CCC49
			rdx *= rax;             //imul rdx, rax
			rax = 0xB698B1C9E93059C1;               //mov rax, 0xB698B1C9E93059C1
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 2:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA8BD6]
			rax = r11;              //mov rax, r11
			rax = imageBase;           //sub rax, [rsp+0x78] -- didn't find trace -> use base
			rax -= 0x2C38EA16;              //sub rax, 0x2C38EA16
			rdx ^= rax;             //xor rdx, rax
			rax = 0xB4B93D59D2681089;               //mov rax, 0xB4B93D59D2681089
			rdx *= rax;             //imul rdx, rax
			rdx += r11;             //add rdx, r11
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD48777D]
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD487955]
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax = rdx;              //mov rax, rdx
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax >>= 0x38;           //shr rax, 0x38
			rcx ^= r10;             //xor rcx, r10
			rdx ^= rax;             //xor rdx, rax
			rax = 0x1CE3CAA84AA7682A;               //mov rax, 0x1CE3CAA84AA7682A
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rdx, [rcx+0x09]
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 3:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA86D6]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xB;            //shr rax, 0x0B
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x16;           //shr rax, 0x16
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2C;           //shr rax, 0x2C
			rdx ^= rax;             //xor rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = 0x131F56B1238D73B5;               //mov rax, 0x131F56B1238D73B5
			rdx *= rax;             //imul rdx, rax
			rcx ^= r10;             //xor rcx, r10
			rax = 0x1035435E575B6C59;               //mov rax, 0x1035435E575B6C59
			rdx -= rax;             //sub rdx, rax
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rdx, [rcx+0x09]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 4:
		{
			//failed to translate: pop rdx
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA822D]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = 0x4122953E9B59DAE5;               //mov rax, 0x4122953E9B59DAE5
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD486DF4]
			rdx -= rax;             //sub rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = r11;              //mov rax, r11
			rax = imageBase;           //sub rax, [rsp+0x78] -- didn't find trace -> use base
			rax -= 0x58348A4C;              //sub rax, 0x58348A4C
			rdx ^= rax;             //xor rdx, rax
			rax = 0x2D70BFA88C1DE299;               //mov rax, 0x2D70BFA88C1DE299
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 5:
		{
			r12 = imageBase + 0x6716;          //lea r12, [0xFFFFFFFFFD48D23F]
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA7CF6]
			rdx ^= r11;             //xor rdx, r11
			rax = 0x37669064BDFE9EA;                //mov rax, 0x37669064BDFE9EA
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
			rdx += r11;             //add rdx, r11
			uintptr_t RSP_0x48;
			RSP_0x48 = imageBase + 0x21D5F0D4;                 //lea rax, [0x000000001F1E5C1B] : RSP+0x48
			rdx += RSP_0x48;                //add rdx, [rsp+0x48]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = 0x8C4AA275AFE07453;               //mov rax, 0x8C4AA275AFE07453
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xF;            //shr rax, 0x0F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rcx = rdx;              //mov rcx, rdx
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rdx ^= rcx;             //xor rdx, rcx
			rax = r11;              //mov rax, r11
			rax ^= r12;             //xor rax, r12
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 6:
		{
			//failed to translate: pop rdx
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA788E]
			r15 = imageBase + 0x3FF1F77A;              //lea r15, [0x000000003D3A5DD2]
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rdx += rax;             //add rdx, rax
			rdx += rcx;             //add rdx, rcx
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x6;            //shr rax, 0x06
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xC;            //shr rax, 0x0C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rcx = r11;              //mov rcx, r11
			rax >>= 0x18;           //shr rax, 0x18
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD4862B7]
			rcx -= rax;             //sub rcx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x30;           //shr rax, 0x30
			rcx -= 0x14449F64;              //sub rcx, 0x14449F64
			rcx ^= rax;             //xor rcx, rax
			rdx ^= rcx;             //xor rdx, rcx
			rax = rdx;              //mov rax, rdx
			rax >>= 0x8;            //shr rax, 0x08
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0x1BC2C247FD97588F;               //mov rax, 0x1BC2C247FD97588F
			rdx ^= rax;             //xor rdx, rax
			rax = 0xE2D3224BC82DCA86;               //mov rax, 0xE2D3224BC82DCA86
			rdx ^= rax;             //xor rdx, rax
			rax = 0x952977A961DEF5B5;               //mov rax, 0x952977A961DEF5B5
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 7:
		{
			r12 = imageBase + 0x6DA1;          //lea r12, [0xFFFFFFFFFD48CED2]
			r9 = driver::read<uintptr_t>(imageBase + 0x7821223);               //mov r9, [0x0000000004CA72DA]
			rax = rdx;              //mov rax, rdx
			rax >>= 0xC;            //shr rax, 0x0C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x18;           //shr rax, 0x18
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x30;           //shr rax, 0x30
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD485F4A]
			rdx += rax;             //add rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rdx ^= r12;             //xor rdx, r12
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rax = driver::read<uintptr_t>(rax + 0x9);               //mov rax, [rax+0x09]
			uintptr_t RSP_0x28;
			RSP_0x28 = 0x11156F7E6912ED7D;          //mov rax, 0x11156F7E6912ED7D : RSP+0x28
			rax *= RSP_0x28;                //imul rax, [rsp+0x28]
			rdx *= rax;             //imul rdx, rax
			rax = 0x8442A66056336123;               //mov rax, 0x8442A66056336123
			rdx ^= rax;             //xor rdx, rax
			rax = r11;              //mov rax, r11
			rax = imageBase;           //sub rax, [rsp+0x78] -- didn't find trace -> use base
			rax += 0xFFFFFFFFFFFF59E1;              //add rax, 0xFFFFFFFFFFFF59E1
			rdx += rax;             //add rdx, rax
			rax = imageBase + 0x3B3BDD34;              //lea rax, [0x0000000038843A3F]
			rax -= r11;             //sub rax, r11
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 8:
		{
			r9 = driver::read<uintptr_t>(imageBase + 0x7821223);               //mov r9, [0x0000000004CA6D14]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD4859C3]
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x7;            //shr rax, 0x07
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xE;            //shr rax, 0x0E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rdx ^= rax;             //xor rdx, rax
			rax = 0xFE54433AB99670D9;               //mov rax, 0xFE54433AB99670D9
			rdx *= rax;             //imul rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rax = driver::read<uintptr_t>(rax + 0x9);               //mov rax, [rax+0x09]
			uintptr_t RSP_0x28;
			RSP_0x28 = 0x707C989E1DF75A21;          //mov rax, 0x707C989E1DF75A21 : RSP+0x28
			rax *= RSP_0x28;                //imul rax, [rsp+0x28]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD4859D2]
			rdx ^= rax;             //xor rdx, rax
			rax = 0x3E789F5419565466;               //mov rax, 0x3E789F5419565466
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 9:
		{
			r12 = imageBase + 0x5F624819;              //lea r12, [0x000000005CAA9E26]
			r9 = driver::read<uintptr_t>(imageBase + 0x7821223);               //mov r9, [0x0000000004CA67DB]
			rax = r12;              //mov rax, r12
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rax ^= r11;             //xor rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x10;           //shr rax, 0x10
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = 0x2D56E8150613B67A;               //mov rax, 0x2D56E8150613B67A
			rdx -= rax;             //sub rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD485523]
			rdx ^= rax;             //xor rdx, rax
			rax = 0xCB760501238D6C11;               //mov rax, 0xCB760501238D6C11
			rdx *= rax;             //imul rdx, rax
			rax = 0x4FBDE321E4E187DD;               //mov rax, 0x4FBDE321E4E187DD
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 10:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA62CD]
			r12 = imageBase + 0x50F0C2A6;              //lea r12, [0x000000004E39133D]
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rax *= r12;             //imul rax, r12
			rdx += rax;             //add rdx, rax
			rax = 0x5D20D5819D812B0E;               //mov rax, 0x5D20D5819D812B0E
			rdx ^= rax;             //xor rdx, rax
			rax = 0xB0C6DE8FE5EC7286;               //mov rax, 0xB0C6DE8FE5EC7286
			rdx ^= rax;             //xor rdx, rax
			rdx -= r11;             //sub rdx, r11
			rax = 0x8F3C63ED5E5ACF53;               //mov rax, 0x8F3C63ED5E5ACF53
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase + 0x628C;          //lea rax, [0xFFFFFFFFFD48B19B]
			rax -= r11;             //sub rax, r11
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rdx += rax;             //add rdx, rax
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rdx, [rcx+0x09]
			return rdx;
		}
		case 11:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA5E26]
			r15 = imageBase + 0x620DA68E;              //lea r15, [0x000000005F55F27E]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x17;           //shr rax, 0x17
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2E;           //shr rax, 0x2E
			rdx ^= rax;             //xor rdx, rax
			rax = r15;              //mov rax, r15
			rax ^= r11;             //xor rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0xAE5536B2D6AC7D85;               //mov rax, 0xAE5536B2D6AC7D85
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD4849A2]
			rdx += rax;             //add rdx, rax
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			uintptr_t RSP_0x48;
			RSP_0x48 = imageBase + 0xA254;             //lea rax, [0xFFFFFFFFFD48EE12] : RSP+0x48
			rax *= RSP_0x48;                //imul rax, [rsp+0x48]
			rdx += rax;             //add rdx, rax
			rax = 0x70A5567341388F09;               //mov rax, 0x70A5567341388F09
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD484A15]
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 12:
		{
			r12 = imageBase + 0x2F3844CA;              //lea r12, [0x000000002C808BB5]
			r9 = driver::read<uintptr_t>(imageBase + 0x7821223);               //mov r9, [0x0000000004CA58C3]
			rax = imageBase + 0xB4F0;          //lea rax, [0xFFFFFFFFFD48FA7C]
			rax = ~rax;             //not rax
			rax *= r11;             //imul rax, r11
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xC;            //shr rax, 0x0C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x18;           //shr rax, 0x18
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x30;           //shr rax, 0x30
			rdx ^= rax;             //xor rdx, rax
			rax = r12;              //mov rax, r12
			rax = ~rax;             //not rax
			rax -= r11;             //sub rax, r11
			rdx += rax;             //add rdx, rax
			rax = 0xEC9CBB3752ACA0AD;               //mov rax, 0xEC9CBB3752ACA0AD
			rdx *= rax;             //imul rdx, rax
			rdx += r11;             //add rdx, r11
			rax = 0x444363F4A500959E;               //mov rax, 0x444363F4A500959E
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = 0xA0C47D17C58A0559;               //mov rax, 0xA0C47D17C58A0559
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 13:
		{
			//failed to translate: pop rdx
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA5440]
			r13 = imageBase + 0x25C2E896;              //lea r13, [0x00000000230B2AA0]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x19;           //shr rax, 0x19
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x32;           //shr rax, 0x32
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase + 0x62966F05;              //lea rax, [0x000000005FDEAE12]
			rax += r11;             //add rax, r11
			rdx ^= rax;             //xor rdx, rax
			rax = 0xFF099BB3AB88BA97;               //mov rax, 0xFF099BB3AB88BA97
			rdx *= rax;             //imul rdx, rax
			rdx -= r11;             //sub rdx, r11
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = rdx;              //mov rax, rdx
			rcx ^= r10;             //xor rcx, r10
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx = r13;              //mov rdx, r13
			rdx = ~rdx;             //not rdx
			rax *= driver::read<uintptr_t>(rcx + 0x9);              //imul rax, [rcx+0x09]
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 14:
		{
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA4F4B]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= driver::read<uintptr_t>(rax + 0x9);              //imul rdx, [rax+0x09]
			rax = 0x8E93F56EEFBABF67;               //mov rax, 0x8E93F56EEFBABF67
			rdx *= rax;             //imul rdx, rax
			rax = 0x531487C50C675851;               //mov rax, 0x531487C50C675851
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x19;           //shr rax, 0x19
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x32;           //shr rax, 0x32
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xE;            //shr rax, 0x0E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x19;           //shr rax, 0x19
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x32;           //shr rax, 0x32
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rcx = imageBase + 0x61F1;          //lea rcx, [0xFFFFFFFFFD489C35]
			rax >>= 0x13;           //shr rax, 0x13
			rcx = ~rcx;             //not rcx
			rdx ^= rax;             //xor rdx, rax
			rax = r11;              //mov rax, r11
			rax = ~rax;             //not rax
			rcx *= rax;             //imul rcx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			rdx += rcx;             //add rdx, rcx
			return rdx;
		}
		case 15:
		{
			//failed to translate: pop rdx
			r10 = driver::read<uintptr_t>(imageBase + 0x7821223);              //mov r10, [0x0000000004CA4AB6]
			r12 = imageBase + 0x7B4A67C4;              //lea r12, [0x000000007892A044]
			rax = 0x2193B3A646C10871;               //mov rax, 0x2193B3A646C10871
			rdx *= rax;             //imul rdx, rax
			rdx ^= r11;             //xor rdx, r11
			rax = 0x569717F7DAB262A0;               //mov rax, 0x569717F7DAB262A0
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xE;            //shr rax, 0x0E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rax ^= rdx;             //xor rax, rdx
			rdx = imageBase + 0x9AC5;          //lea rdx, [0xFFFFFFFFFD48D02C]
			rax += r11;             //add rax, r11
			rdx += rax;             //add rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rax = r12;              //mov rax, r12
			rax ^= r11;             //xor rax, r11
			rax -= r11;             //sub rax, r11
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx += rax;             //add rdx, rax
			rdx *= driver::read<uintptr_t>(rcx + 0x9);              //imul rdx, [rcx+0x09]
			return rdx;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = index;
		rcx = rbx * 0x13C8;
		rax = 0x4AD2CE6C11F9A497;               //mov rax, 0x4AD2CE6C11F9A497
		r11 = imageBase;           //lea r11, [0xFFFFFFFFFD8377D3]
		rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
		r10 = 0xF9DE825D26E3B99B;               //mov r10, 0xF9DE825D26E3B99B
		rdx >>= 0xB;            //shr rdx, 0x0B
		rax = rdx * 0x1B5F;             //imul rax, rdx, 0x1B5F
		rcx -= rax;             //sub rcx, rax
		rax = 0x3B0E039359376BE7;               //mov rax, 0x3B0E039359376BE7
		r8 = rcx * 0x1B5F;              //imul r8, rcx, 0x1B5F
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rdx >>= 0xB;            //shr rdx, 0x0B
		rax = rdx * 0x22AE;             //imul rax, rdx, 0x22AE
		r8 -= rax;              //sub r8, rax
		rax = 0x97B425ED097B425F;               //mov rax, 0x97B425ED097B425F
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = 0x8F1779D9FDC3A219;               //mov rax, 0x8F1779D9FDC3A219
		rdx >>= 0x5;            //shr rdx, 0x05
		rcx = rdx * 0x36;               //imul rcx, rdx, 0x36
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rdx >>= 0x7;            //shr rdx, 0x07
		rcx += rdx;             //add rcx, rdx
		rax = rcx * 0x1CA;              //imul rax, rcx, 0x1CA
		rcx = r8 * 0x1CC;               //imul rcx, r8, 0x1CC
		rcx -= rax;             //sub rcx, rax
		rax = driver::read<uint16_t>(rcx + r11 * 1 + 0x7834840);                //movzx eax, word ptr [rcx+r11*1+0x7834840]
		r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
		rax = r10;              //mov rax, r10
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r10;              //mov rax, r10
		rdx >>= 0xD;            //shr rdx, 0x0D
		rcx = rdx * 0x20C9;             //imul rcx, rdx, 0x20C9
		r8 -= rcx;              //sub r8, rcx
		r9 = r8 * 0x3ED7;               //imul r9, r8, 0x3ED7
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0xD;            //shr rdx, 0x0D
		rax = rdx * 0x20C9;             //imul rax, rdx, 0x20C9
		r9 -= rax;              //sub r9, rax
		rax = 0x3521CFB2B78C1353;               //mov rax, 0x3521CFB2B78C1353
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x7;            //shr rax, 0x07
		rcx = rax * 0xD4;               //imul rcx, rax, 0xD4
		rax = 0x5C9882B931057263;               //mov rax, 0x5C9882B931057263
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x5;            //shr rax, 0x05
		rcx += rax;             //add rcx, rax
		rax = rcx * 0x5E;               //imul rax, rcx, 0x5E
		rcx = r9 + r9 * 2;              //lea rcx, [r9+r9*2]
		rcx <<= 0x5;            //shl rcx, 0x05
		rcx -= rax;             //sub rcx, rax
		rsi = driver::read<uint16_t>(rcx + r11 * 1 + 0x783A8E0);                //movsx esi, word ptr [rcx+r11*1+0x783A8E0]
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