#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
	extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = readMemory<uintptr_t>(imageBase + 0x1806E058);
		if (!rbx)
			return rbx;
		r8 = peb;               //mov r8, gs:[rax]
		rax = rbx;              //mov rax, rbx
		rax >>= 0xD;            //shr rax, 0x0D
		rbx ^= rax;             //xor rbx, rax
		rax = rbx;              //mov rax, rbx
		rax >>= 0x1A;           //shr rax, 0x1A
		rbx ^= rax;             //xor rbx, rax
		rax = 0x75AC52C47565F299;               //mov rax, 0x75AC52C47565F299
		rdx = rbx;              //mov rdx, rbx
		rdx >>= 0x34;           //shr rdx, 0x34
		rdx ^= rbx;             //xor rdx, rbx
		rdx *= rax;             //imul rdx, rax
		rax = 0x3F38F2AE23228E30;               //mov rax, 0x3F38F2AE23228E30
		rdx -= rax;             //sub rdx, rax
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
		rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
		rax >>= 0x38;           //shr rax, 0x38
		rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
		rax ^= rdx;             //xor rax, rdx
		rcx ^= readMemory<uintptr_t>(imageBase + 0x71D90F2);             //xor rcx, [0x0000000004E90B48]
		rcx = ~rcx;             //not rcx
		rbx = readMemory<uintptr_t>(rcx + 0x13);              //mov rbx, [rcx+0x13]
		rbx *= rax;             //imul rbx, rax
		rbx -= r8;              //sub rbx, r8
		return rbx;
	}

	extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rax = readMemory<uintptr_t>(clientInfo + 0x9fde8);
		if (!rax)
			return rax;
		rdi = peb;              //mov rdi, gs:[rcx]
		rcx = rdi;              //mov rcx, rdi
		rcx = _rotr64(rcx, 0x13);               //ror rcx, 0x13
		rcx &= 0xF;
		switch (rcx) {
		case 0:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB79CF]
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E90A62]
			rcx = rdi;              //mov rcx, rdi
			rcx = ~rcx;             //not rcx
			rcx -= rbx;             //sub rcx, rbx
			rcx += 0xFFFFFFFFFFFFB03D;              //add rcx, 0xFFFFFFFFFFFFB03D
			rax += rcx;             //add rax, rcx
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
			rax -= rbx;             //sub rax, rbx
			rcx = 0x17018B6945529074;               //mov rcx, 0x17018B6945529074
			rax += rcx;             //add rax, rcx
			rcx = 0xBC9C2D260721DFFD;               //mov rcx, 0xBC9C2D260721DFFD
			rax *= rcx;             //imul rax, rcx
			rax += rbx;             //add rax, rbx
			rcx = 0xA9FC06249DFE0873;               //mov rcx, 0xA9FC06249DFE0873
			rax *= rcx;             //imul rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			return rax;
		}
		case 1:
		{
			r11 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r11, [0x0000000004E9057D]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB7447]
			rdx = imageBase + 0x290C;          //lea rdx, [0xFFFFFFFFFDCB9CFD]
			rcx = 0xAB38D0F7B94B733D;               //mov rcx, 0xAB38D0F7B94B733D
			rax *= rcx;             //imul rax, rcx
			r15 = 0xF4AD9C5147247AE8;               //mov r15, 0xF4AD9C5147247AE8
			rcx = rdi;              //mov rcx, rdi
			rcx *= rdx;             //imul rcx, rdx
			rcx -= rbx;             //sub rcx, rbx
			rcx += r15;             //add rcx, r15
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1D;           //shr rcx, 0x1D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3A;           //shr rcx, 0x3A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r11;             //xor rcx, r11
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rcx = 0x1202F95890F87C8;                //mov rcx, 0x1202F95890F87C8
			rax -= rcx;             //sub rax, rcx
			return rax;
		}
		case 2:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E9011C]
			rcx = rdi * 0xFE;                 //imul rcx, rdi, 0xFFFFFFFFFFFFFFFE
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x22;           //shr rcx, 0x22
			rax ^= rcx;             //xor rax, rcx
			rax += rdi;             //add rax, rdi
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = 0x432859FC2C7367E7;               //mov rcx, 0x432859FC2C7367E7
			rax *= rcx;             //imul rax, rcx
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rcx = rax;              //mov rcx, rax
			rdx ^= r10;             //xor rdx, r10
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rdx = ~rdx;             //not rdx
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rcx ^= rax;             //xor rcx, rax
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			rcx = 0x1CABBB23FD8D639B;               //mov rcx, 0x1CABBB23FD8D639B
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 3:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB6C79]
			r15 = imageBase + 0x3483EDA1;              //lea r15, [0x00000000324F5A02]
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8FD42]
			r11 = 0xE95C245BB2EE5516;               //mov r11, 0xE95C245BB2EE5516
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			rcx = readMemory<uintptr_t>(rcx + 0x5);               //mov rcx, [rcx+0x05]
			rcx *= rax;             //imul rcx, rax
			rax = r15;              //mov rax, r15
			rcx += rdi;             //add rcx, rdi
			rax = ~rax;             //not rax
			rax += r11;             //add rax, r11
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x14;           //shr rcx, 0x14
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x28;           //shr rcx, 0x28
			rax ^= rcx;             //xor rax, rcx
			rax -= rdi;             //sub rax, rdi
			rcx = 0x3555A17B83EFB3C7;               //mov rcx, 0x3555A17B83EFB3C7
			rax *= rcx;             //imul rax, rcx
			rcx = 0x160C6CDD5F954A38;               //mov rcx, 0x160C6CDD5F954A38
			rax -= rdi;             //sub rax, rdi
			rax -= rbx;             //sub rax, rbx
			rax -= 0x2DF62A23;              //sub rax, 0x2DF62A23
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 4:
		{
			r15 = imageBase + 0xC7B6;          //lea r15, [0xFFFFFFFFFDCC3039]
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8F931]
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rcx = rdi + rax * 1;            //lea rcx, [rdi+rax*1]
			rdx = ~rdx;             //not rdx
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			rcx = 0x78D66A1CE27478D3;               //mov rcx, 0x78D66A1CE27478D3
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
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1F;           //shr rcx, 0x1F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3E;           //shr rcx, 0x3E
			rax ^= rcx;             //xor rax, rcx
			rcx = imageBase + 0x6741;          //lea rcx, [0xFFFFFFFFFDCBCDEE]
			rcx = ~rcx;             //not rcx
			rcx += rax;             //add rcx, rax
			rax = rdi + 0x1;                //lea rax, [rdi+0x01]
			rax += rcx;             //add rax, rcx
			rax ^= rdi;             //xor rax, rdi
			rax ^= r15;             //xor rax, r15
			rcx = 0x24BCCA0B53388AEA;               //mov rcx, 0x24BCCA0B53388AEA
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 5:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB62E5]
			rdx = imageBase + 0x8569;          //lea rdx, [0xFFFFFFFFFDCBE836]
			r15 = imageBase + 0xAA0B;          //lea r15, [0xFFFFFFFFFDCC0CCC]
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8F39B]
			rcx = rdx;              //mov rcx, rdx
			rcx = ~rcx;             //not rcx
			rcx ^= rdi;             //xor rcx, rdi
			rax -= rcx;             //sub rax, rcx
			rcx = 0x9B31E206C1CDD5C3;               //mov rcx, 0x9B31E206C1CDD5C3
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xC;            //shr rcx, 0x0C
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x18;           //shr rcx, 0x18
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x30;           //shr rcx, 0x30
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rcx = 0xF51E2A85F29A70B;                //mov rcx, 0xF51E2A85F29A70B
			rax -= rcx;             //sub rax, rcx
			rcx = 0x8989152276BB82D6;               //mov rcx, 0x8989152276BB82D6
			rax ^= rcx;             //xor rax, rcx
			rax -= rbx;             //sub rax, rbx
			rax += 0xFFFFFFFFFFFF37F0;              //add rax, 0xFFFFFFFFFFFF37F0
			rax += rdi;             //add rax, rdi
			rax ^= rdi;             //xor rax, rdi
			rax ^= r15;             //xor rax, r15
			return rax;
		}
		case 6:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB5D91]
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E8EE69]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rcx = rbx + 0x2db6eaaf;                 //lea rcx, [rbx+0x2DB6EAAF]
			rcx += rdi;             //add rcx, rdi
			rax ^= rcx;             //xor rax, rcx
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
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1A;           //shr rcx, 0x1A
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x34;           //shr rcx, 0x34
			rcx ^= rdi;             //xor rcx, rdi
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x53575B3471D30C52;               //mov rcx, 0x53575B3471D30C52
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x83CC6E096B7D5731;               //mov rcx, 0x83CC6E096B7D5731
			rax *= rcx;             //imul rax, rcx
			rcx = 0x2D268BD6FF3B4A65;               //mov rcx, 0x2D268BD6FF3B4A65
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 7:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8EA31]
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB58FB]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r10;             //xor rcx, r10
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rcx = 0x1FE961BC0D596901;               //mov rcx, 0x1FE961BC0D596901
			rax += rcx;             //add rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rcx = 0xEABC3B3886A0E103;               //mov rcx, 0xEABC3B3886A0E103
			rax *= rcx;             //imul rax, rcx
			rax += rbx;             //add rax, rbx
			rdx = rdi;              //mov rdx, rdi
			rdx = ~rdx;             //not rdx
			rcx = imageBase + 0x7525;          //lea rcx, [0xFFFFFFFFFDCBCB48]
			rdx += rcx;             //add rdx, rcx
			rcx = rax;              //mov rcx, rax
			rax = 0x37B2F642B57F479;                //mov rax, 0x37B2F642B57F479
			rcx *= rax;             //imul rcx, rax
			rax = rdx;              //mov rax, rdx
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 8:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB5488]
			r11 = imageBase + 0x54BDDC6C;              //lea r11, [0x00000000528930DC]
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E8E547]
			rax -= rbx;             //sub rax, rbx
			rax += 0xFFFFFFFFB0267D85;              //add rax, 0xFFFFFFFFB0267D85
			rax += rdi;             //add rax, rdi
			rcx = 0xDD7BD2E06188E77F;               //mov rcx, 0xDD7BD2E06188E77F
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x76E83A4EECA680A9;               //mov rcx, 0x76E83A4EECA680A9
			rax *= rcx;             //imul rax, rcx
			rcx = 0x6F616717865D112B;               //mov rcx, 0x6F616717865D112B
			rax += rcx;             //add rax, rcx
			rcx = r11;              //mov rcx, r11
			rcx = ~rcx;             //not rcx
			rcx ^= rdi;             //xor rcx, rdi
			rax -= rcx;             //sub rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rax ^= rdi;             //xor rax, rdi
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x20;           //shr rcx, 0x20
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 9:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8E072]
			rbx = imageBase + 0x285FB43A;              //lea rbx, [0x00000000262B0365]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xF;            //shr rcx, 0x0F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			uintptr_t RSP_0x78;
			RSP_0x78 = 0x4BBFA56727DC4AB9;          //mov rcx, 0x4BBFA56727DC4AB9 : RSP+0x78
			rax *= RSP_0x78;                //imul rax, [rsp+0x78]
			rcx = rbx;              //mov rcx, rbx
			rcx = ~rcx;             //not rcx
			rcx += rdi;             //add rcx, rdi
			rcx ^= rax;             //xor rcx, rax
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = ~rdx;             //not rdx
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1B;           //shr rcx, 0x1B
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x36;           //shr rcx, 0x36
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x6EB4862326CD9433;               //mov rcx, 0x6EB4862326CD9433
			rax -= rcx;             //sub rax, rcx
			rcx = 0x2A7CA7719C633418;               //mov rcx, 0x2A7CA7719C633418
			rax ^= rcx;             //xor rax, rcx
			rax += rdi;             //add rax, rdi
			return rax;
		}
		case 10:
		{
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E8DAC4]
			rcx = 0xEBB12D2C79FC5652;               //mov rcx, 0xEBB12D2C79FC5652
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x9E6258824936A3C6;               //mov rcx, 0x9E6258824936A3C6
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rax *= readMemory<uintptr_t>(rcx + 0x5);              //imul rax, [rcx+0x05]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1D;           //shr rcx, 0x1D
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3A;           //shr rcx, 0x3A
			rax ^= rcx;             //xor rax, rcx
			rcx = 0x3D6B11E766286AA3;               //mov rcx, 0x3D6B11E766286AA3
			rax *= rcx;             //imul rax, rcx
			rax -= rdi;             //sub rax, rdi
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
			rax -= rdi;             //sub rax, rdi
			return rax;
		}
		case 11:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8D5E1]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x24;           //shr rcx, 0x24
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x17;           //shr rcx, 0x17
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx >>= 0x2E;           //shr rcx, 0x2E
			rcx ^= rax;             //xor rcx, rax
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = ~rdx;             //not rdx
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			rcx = 0x5D5C607174CFC222;               //mov rcx, 0x5D5C607174CFC222
			rax -= rcx;             //sub rax, rcx
			rax -= rdi;             //sub rax, rdi
			rcx = 0x1ACECF0113784AB7;               //mov rcx, 0x1ACECF0113784AB7
			rax *= rcx;             //imul rax, rcx
			rax += rdi;             //add rax, rdi
			rcx = 0x7BD4F3E5AB768887;               //mov rcx, 0x7BD4F3E5AB768887
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		case 12:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB3FA2]
			r15 = imageBase + 0x6171;          //lea r15, [0xFFFFFFFFFDCBA0FB]
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8D084]
			rcx = rdi;              //mov rcx, rdi
			rcx ^= r15;             //xor rcx, r15
			rax += rcx;             //add rax, rcx
			rax ^= rbx;             //xor rax, rbx
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx = rax;              //mov rcx, rax
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rax = 0x673E272C0CA883CD;               //mov rax, 0x673E272C0CA883CD
			rcx ^= rax;             //xor rcx, rax
			rdx = ~rdx;             //not rdx
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			rcx = rdi;              //mov rcx, rdi
			rcx = ~rcx;             //not rcx
			rax += rcx;             //add rax, rcx
			rax -= rbx;             //sub rax, rbx
			rax -= 0x191C62F6;              //sub rax, 0x191C62F6
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x27;           //shr rcx, 0x27
			rax ^= rcx;             //xor rax, rcx
			rcx = 0xE12F42EFE3D58BCB;               //mov rcx, 0xE12F42EFE3D58BCB
			rax *= rcx;             //imul rax, rcx
			rcx = 0x285DF5F4C95F3162;               //mov rcx, 0x285DF5F4C95F3162
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 13:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB3B5A]
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E8CC04]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rcx = readMemory<uintptr_t>(rcx + 0x5);               //mov rcx, [rcx+0x05]
			uintptr_t RSP_0x78;
			RSP_0x78 = 0x5910987B2E4C2169;          //mov rcx, 0x5910987B2E4C2169 : RSP+0x78
			rcx *= RSP_0x78;                //imul rcx, [rsp+0x78]
			rax *= rcx;             //imul rax, rcx
			rcx = 0xE2E24EFA6B663414;               //mov rcx, 0xE2E24EFA6B663414
			rax ^= rcx;             //xor rax, rcx
			rax -= rdi;             //sub rax, rdi
			rcx = imageBase + 0x61F;           //lea rcx, [0xFFFFFFFFFDCB3E10]
			rax += rcx;             //add rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x27;           //shr rcx, 0x27
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1;            //shr rcx, 0x01
			rax ^= rcx;             //xor rax, rcx
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
			rcx = rbx + 0x14cab09b;                 //lea rcx, [rbx+0x14CAB09B]
			rcx += rdi;             //add rcx, rdi
			rax -= rbx;             //sub rax, rbx
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 14:
		{
			r9 = readMemory<uintptr_t>(imageBase + 0x71D912F);               //mov r9, [0x0000000004E8C800]
			rcx = rax;              //mov rcx, rax
			rcx >>= 0xF;            //shr rcx, 0x0F
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1E;           //shr rcx, 0x1E
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x3C;           //shr rcx, 0x3C
			rax ^= rcx;             //xor rax, rcx
			rax ^= rdi;             //xor rax, rdi
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x1;            //shr rcx, 0x01
			rax ^= rcx;             //xor rax, rcx
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
			rcx = 0x8ADDB5A6833CD70C;               //mov rcx, 0x8ADDB5A6833CD70C
			rax += rcx;             //add rax, rcx
			rcx = 0x71785D8AD6471764;               //mov rcx, 0x71785D8AD6471764
			rax ^= rcx;             //xor rax, rcx
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= r9;              //xor rcx, r9
			rcx = ~rcx;             //not rcx
			rcx = readMemory<uintptr_t>(rcx + 0x5);               //mov rcx, [rcx+0x05]
			uintptr_t RSP_0x70;
			RSP_0x70 = 0xC2A87682DDC9E25D;          //mov rcx, 0xC2A87682DDC9E25D : RSP+0x70
			rcx *= RSP_0x70;                //imul rcx, [rsp+0x70]
			rax *= rcx;             //imul rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x21;           //shr rcx, 0x21
			rax ^= rcx;             //xor rax, rcx
			return rax;
		}
		case 15:
		{
			rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCB3204]
			r13 = 0x3C85E73829FCC7AD;               //mov r13, 0x3C85E73829FCC7AD
			r10 = readMemory<uintptr_t>(imageBase + 0x71D912F);              //mov r10, [0x0000000004E8C2C9]
			rax *= r13;             //imul rax, r13
			rcx = 0xE37E90332B6845B6;               //mov rcx, 0xE37E90332B6845B6
			rax ^= rcx;             //xor rax, rcx
			rcx = rax;              //mov rcx, rax
			rcx >>= 0x24;           //shr rcx, 0x24
			rax ^= rcx;             //xor rax, rcx
			rax += rbx;             //add rax, rbx
			rax ^= rdi;             //xor rax, rdi
			rax += rbx;             //add rax, rbx
			rcx = rax;              //mov rcx, rax
			rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
			rcx >>= 0x28;           //shr rcx, 0x28
			rcx ^= rax;             //xor rcx, rax
			rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
			rdx ^= r10;             //xor rdx, r10
			rdx = ~rdx;             //not rdx
			rax = readMemory<uintptr_t>(rdx + 0x5);               //mov rax, [rdx+0x05]
			rax *= rcx;             //imul rax, rcx
			return rax;
		}
		}
	}

	extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rdx = readMemory<uintptr_t>(imageBase + 0x15E18A18);
		if (!rdx)
			return rdx;
		r8 = ~peb;               //mov r8, gs:[rax]
		rax = r8;               //mov rax, r8
		rax = _rotl64(rax, 0x26);               //rol rax, 0x26
		rax &= 0xF;
		switch (rax) {
		case 0:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov r10, [0x0000000004B6109C]
			r14 = imageBase + 0x676D94A3;              //lea r14, [0x00000000650612DD]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3;            //shr rax, 0x03
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x6;            //shr rax, 0x06
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
			rax = 0xD635FD6F5740DF17;               //mov rax, 0xD635FD6F5740DF17
			rdx *= rax;             //imul rdx, rax
			rax = r8;               //mov rax, r8
			rax *= r14;             //imul rax, r14
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = imageBase + 0x3496E896;              //lea rax, [0x00000000322F641C]
			r13 = 0x891801D00A4665B;                //mov r13, 0x891801D00A4665B
			rax = ~rax;             //not rax
			rax -= r8;              //sub rax, r8
			rax += r13;             //add rax, r13
			rdx += rax;             //add rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD987D29]
			rdx ^= rax;             //xor rdx, rax
			rax = 0x3059E19BF5C898E5;               //mov rax, 0x3059E19BF5C898E5
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 1:
		{
			//failed to translate: pop rdx
			r12 = imageBase + 0x74050ED8;              //lea r12, [0x00000000719D87A4]
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B60AB3]
			rax = r12;              //mov rax, r12
			rax -= r8;              //sub rax, r8
			rdx += rax;             //add rdx, rax
			rdx -= r8;              //sub rdx, r8
			rdx ^= r8;              //xor rdx, r8
			rax = 0x5BB3382495788FD9;               //mov rax, 0x5BB3382495788FD9
			rdx *= rax;             //imul rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax = 0x5B9DDF9B7BC38403;               //mov rax, 0x5B9DDF9B7BC38403
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax += rdx;             //add rax, rdx
			rcx ^= rbx;             //xor rcx, rbx
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx = readMemory<uintptr_t>(rcx + 0xb);               //mov rdx, [rcx+0x0B]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x20;           //shr rax, 0x20
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 2:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B605A6]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax = rdx;              //mov rax, rdx
			rcx ^= rbx;             //xor rcx, rbx
			rax >>= 0x24;           //shr rax, 0x24
			rax ^= rdx;             //xor rax, rdx
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx = readMemory<uintptr_t>(rcx + 0xb);               //mov rdx, [rcx+0x0B]
			rdx *= rax;             //imul rdx, rax
			rcx = r8;               //mov rcx, r8
			rcx = ~rcx;             //not rcx
			rax = imageBase + 0x8D63;          //lea rax, [0xFFFFFFFFFD98FD2E]
			rdx += rax;             //add rdx, rax
			rdx += rcx;             //add rdx, rcx
			rax = 0xFF36F9B289267D23;               //mov rax, 0xFF36F9B289267D23
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x26;           //shr rax, 0x26
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r8;              //xor rdx, r8
			rax = 0x1FC63BF66339890F;               //mov rax, 0x1FC63BF66339890F
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 3:
		{
			//failed to translate: pop rdx
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B6014B]
			rdx += r8;              //add rdx, r8
			rax = rdx;              //mov rax, rdx
			rax >>= 0xF;            //shr rax, 0x0F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3C;           //shr rax, 0x3C
			rdx ^= rax;             //xor rdx, rax
			rax = 0x3437489FC93631C1;               //mov rax, 0x3437489FC93631C1
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x5;            //shr rax, 0x05
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xA;            //shr rax, 0x0A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3;            //shr rax, 0x03
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x6;            //shr rax, 0x06
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
			rdx -= r8;              //sub rdx, r8
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rcx ^= rbx;             //xor rcx, rbx
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD986BCF]
			rdx -= rax;             //sub rdx, rax
			rax = 0xFDF3D74B7A69C45B;               //mov rax, 0xFDF3D74B7A69C45B
			rax *= rdx;             //imul rax, rdx
			rdx = 0x52547ABD86BE0CB4;               //mov rdx, 0x52547ABD86BE0CB4
			rax += rdx;             //add rax, rdx
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx = readMemory<uintptr_t>(rcx + 0xb);               //mov rdx, [rcx+0x0B]
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 4:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5FB42]
			rax = r8;               //mov rax, r8
			rax = imageBase;           //sub rax, [rbp+0x48] -- didn't find trace -> use base
			rax -= 0x4929CCC0;              //sub rax, 0x4929CCC0
			rdx ^= rax;             //xor rdx, rax
			rax = r8;               //mov rax, r8
			rax = ~rax;             //not rax
			uintptr_t RSP_0x48;
			RSP_0x48 = imageBase + 0x6D8B;             //lea rax, [0xFFFFFFFFFD98D6D9] : RSP+0x48
			rax += RSP_0x48;                //add rax, [rsp+0x48]
			rdx ^= rax;             //xor rdx, rax
			rax = 0x46B53CB403B92895;               //mov rax, 0x46B53CB403B92895
			rdx += rax;             //add rdx, rax
			rax = 0xCCE222429417FA02;               //mov rax, 0xCCE222429417FA02
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9866AB]
			rdx -= rax;             //sub rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rax = readMemory<uintptr_t>(rax + 0xb);               //mov rax, [rax+0x0B]
			uintptr_t RSP_0x78;
			RSP_0x78 = 0xA6572F476EA14F7B;          //mov rax, 0xA6572F476EA14F7B : RSP+0x78
			rax *= RSP_0x78;                //imul rax, [rsp+0x78]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xF;            //shr rax, 0x0F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1E;           //shr rax, 0x1E
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3C;           //shr rax, 0x3C
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 5:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5F6B0]
			r15 = imageBase + 0xC902;          //lea r15, [0xFFFFFFFFFD992D50]
			rax = r8;               //mov rax, r8
			rax *= r15;             //imul rax, r15
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x12;           //shr rax, 0x12
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x24;           //shr rax, 0x24
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = 0x7887CB49CAD27C83;               //mov rax, 0x7887CB49CAD27C83
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD985FC8]
			rax += 0x5DBA;          //add rax, 0x5DBA
			rax += r8;              //add rax, r8
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
			rax = imageBase + 0xD9F3;          //lea rax, [0xFFFFFFFFFD9938E9]
			rdx -= r8;              //sub rdx, r8
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
			return rdx;
		}
		case 6:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5F099]
			r12 = imageBase + 0x56AD1EF7;              //lea r12, [0x0000000054457D2E]
			rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
			rax = rdx;              //mov rax, rdx
			rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
			rax >>= 0x26;           //shr rax, 0x26
			rcx ^= rbx;             //xor rcx, rbx
			rax ^= rdx;             //xor rax, rdx
			rcx = _byteswap_uint64(rcx);            //bswap rcx
			rdx = readMemory<uintptr_t>(rcx + 0xb);               //mov rdx, [rcx+0x0B]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rcx = rdx;              //mov rcx, rdx
			rcx >>= 0x28;           //shr rcx, 0x28
			rax = 0x73E3C1626886AD89;               //mov rax, 0x73E3C1626886AD89
			rcx ^= rdx;             //xor rcx, rdx
			rdx = r8;               //mov rdx, r8
			rdx *= r12;             //imul rdx, r12
			rdx += rcx;             //add rdx, rcx
			rdx *= rax;             //imul rdx, rax
			rdx -= r8;              //sub rdx, r8
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD985CD4]
			rdx ^= rax;             //xor rdx, rax
			rax = 0x5BE12EB58C328E79;               //mov rax, 0x5BE12EB58C328E79
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 7:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5EBB1]
			rcx = r8 + 0xffffffff946a7cce;          //lea rcx, [r8-0x6B958332]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD985735]
			rdx ^= rax;             //xor rdx, rax
			rdx -= rax;             //sub rdx, rax
			rcx += rdx;             //add rcx, rdx
			rax = rcx;              //mov rax, rcx
			rax >>= 0xC;            //shr rax, 0x0C
			rcx ^= rax;             //xor rcx, rax
			rax = rcx;              //mov rax, rcx
			rax >>= 0x18;           //shr rax, 0x18
			rcx ^= rax;             //xor rcx, rax
			rdx = rcx;              //mov rdx, rcx
			rdx >>= 0x30;           //shr rdx, 0x30
			rax = 0xA2777C64321A6CF;                //mov rax, 0xA2777C64321A6CF
			rdx ^= rcx;             //xor rdx, rcx
			rdx *= rax;             //imul rdx, rax
			rax = 0x3D998F50D02DE848;               //mov rax, 0x3D998F50D02DE848
			rdx -= rax;             //sub rdx, rax
			rdx ^= r8;              //xor rdx, r8
			rax = 0x44777CC2F2CDCF18;               //mov rax, 0x44777CC2F2CDCF18
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 8:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5E82C]
			r12 = imageBase + 0xC270;          //lea r12, [0xFFFFFFFFFD99183A]
			rcx = r8;               //mov rcx, r8
			rax = r12;              //mov rax, r12
			rax = ~rax;             //not rax
			rcx = ~rcx;             //not rcx
			rcx += rax;             //add rcx, rax
			rdx ^= rcx;             //xor rdx, rcx
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rax = readMemory<uintptr_t>(rax + 0xb);               //mov rax, [rax+0x0B]
			rdx *= rax;             //imul rdx, rax
			rax = 0x9F3A04B73F91D7BF;               //mov rax, 0x9F3A04B73F91D7BF
			rdx *= rax;             //imul rdx, rax
			rax = 0x4B4AF50AA7AE5554;               //mov rax, 0x4B4AF50AA7AE5554
			rdx += rax;             //add rdx, rax
			rax = 0x28274EB8C143F7E5;               //mov rax, 0x28274EB8C143F7E5
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x15;           //shr rax, 0x15
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x2A;           //shr rax, 0x2A
			rdx ^= rax;             //xor rdx, rax
			rax = r8;               //mov rax, r8
			rax = imageBase;           //sub rax, [rbp+0x48] -- didn't find trace -> use base
			rax += 0xFFFFFFFFFFFF0C01;              //add rax, 0xFFFFFFFFFFFF0C01
			rdx += rax;             //add rdx, rax
			rax = imageBase + 0x6F41;          //lea rax, [0xFFFFFFFFFD98BF75]
			rax = ~rax;             //not rax
			rax++;
			rax += r8;              //add rax, r8
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 9:
		{
			r10 = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov r10, [0x0000000004B5E1C8]
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rdx += r8;              //add rdx, r8
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD984DD1]
			rax += 0x11B6;          //add rax, 0x11B6
			rax += r8;              //add rax, r8
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD984DBE]
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x5;            //shr rax, 0x05
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0xA;            //shr rax, 0x0A
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = 0x3E29187B34B94B2B;               //mov rax, 0x3E29187B34B94B2B
			rdx *= rax;             //imul rdx, rax
			rax = 0x2FF261694EB43A81;               //mov rax, 0x2FF261694EB43A81
			rdx += rax;             //add rdx, rax
			rax = 0x431D1D596FDAE99B;               //mov rax, 0x431D1D596FDAE99B
			rdx *= rax;             //imul rdx, rax
			return rdx;
		}
		case 10:
		{
			r14 = imageBase + 0x1DD8;          //lea r14, [0xFFFFFFFFFD986885]
			r15 = imageBase + 0x53356CF1;              //lea r15, [0x0000000050CDB792]
			r10 = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov r10, [0x0000000004B5DC7D]
			rax = r8;               //mov rax, r8
			rax = ~rax;             //not rax
			rax ^= r14;             //xor rax, r14
			rdx -= rax;             //sub rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r10;             //xor rax, r10
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = 0x9251D28D0725F547;               //mov rax, 0x9251D28D0725F547
			rdx *= rax;             //imul rdx, rax
			rax = r8;               //mov rax, r8
			rax = ~rax;             //not rax
			rdx ^= rax;             //xor rdx, rax
			rdx ^= r15;             //xor rdx, r15
			rax = 0xB570D6A46CA6BDA;                //mov rax, 0xB570D6A46CA6BDA
			rdx -= rax;             //sub rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = 0xF541FBA8EA6DB70D;               //mov rax, 0xF541FBA8EA6DB70D
			rdx *= rax;             //imul rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9846C7]
			rdx -= rax;             //sub rdx, rax
			return rdx;
		}
		case 11:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5D728]
			r12 = imageBase + 0x7A87E289;              //lea r12, [0x0000000078202743]
			rax = r8;               //mov rax, r8
			rax = ~rax;             //not rax
			uintptr_t RSP_0x48;
			RSP_0x48 = imageBase + 0x4D63C65D;                 //lea rax, [0x000000004AFC0B2F] : RSP+0x48
			rax += RSP_0x48;                //add rax, [rsp+0x48]
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			rax = 0x4386482E23BD7BAB;               //mov rax, 0x4386482E23BD7BAB
			rdx *= rax;             //imul rdx, rax
			rax = r8;               //mov rax, r8
			rax = ~rax;             //not rax
			rax += r12;             //add rax, r12
			rdx ^= rax;             //xor rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD984165]
			rax += 0x5D6A5202;              //add rax, 0x5D6A5202
			rax += r8;              //add rax, r8
			rdx += rax;             //add rdx, rax
			rax = 0x5D0357B59D909B8;                //mov rax, 0x5D0357B59D909B8
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x25;           //shr rax, 0x25
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 12:
		{
			//failed to translate: pop rdx
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5D15B]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = r8;               //mov rax, r8
			rax = imageBase;           //sub rax, [rbp+0x48] -- didn't find trace -> use base
			rax += 0xFFFFFFFFB8A79E69;              //add rax, 0xFFFFFFFFB8A79E69
			rdx += rax;             //add rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rdx -= r8;              //sub rdx, r8
			rax = rdx;              //mov rax, rdx
			rax >>= 0x27;           //shr rax, 0x27
			rdx ^= rax;             //xor rdx, rax
			rdx += r8;              //add rdx, r8
			rax = 0xDC42F705062C7C2B;               //mov rax, 0xDC42F705062C7C2B
			rdx *= rax;             //imul rdx, rax
			rax = 0x22D95990904EF823;               //mov rax, 0x22D95990904EF823
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 13:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5CCD7]
			r15 = imageBase + 0x4C7B;          //lea r15, [0xFFFFFFFFFD9886F0]
			rax = 0x8083BF913D676785;               //mov rax, 0x8083BF913D676785
			rdx *= rax;             //imul rdx, rax
			rax = r15;              //mov rax, r15
			rax = ~rax;             //not rax
			rax *= r8;              //imul rax, r8
			rdx += rax;             //add rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1C;           //shr rax, 0x1C
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x38;           //shr rax, 0x38
			rdx ^= rax;             //xor rdx, rax
			rdx -= r8;              //sub rdx, r8
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD98398C]
			rdx -= rax;             //sub rdx, rax
			rax = 0xA2C3AADF199E32E1;               //mov rax, 0xA2C3AADF199E32E1
			rdx *= rax;             //imul rdx, rax
			rax = 0x23580E1270B613C4;               //mov rax, 0x23580E1270B613C4
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
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x1F;           //shr rax, 0x1F
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x3E;           //shr rax, 0x3E
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		case 14:
		{
			r9 = readMemory<uintptr_t>(imageBase + 0x71D924F);               //mov r9, [0x0000000004B5C707]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD9831F3]
			rdx ^= rax;             //xor rdx, rax
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= r9;              //xor rax, r9
			rax = _byteswap_uint64(rax);            //bswap rax
			rdx *= readMemory<uintptr_t>(rax + 0xb);              //imul rdx, [rax+0x0B]
			rax = rdx;              //mov rax, rdx
			rax >>= 0x14;           //shr rax, 0x14
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x28;           //shr rax, 0x28
			rdx ^= rax;             //xor rdx, rax
			rax = 0x44A70ED11D0E61A3;               //mov rax, 0x44A70ED11D0E61A3
			rdx -= rax;             //sub rdx, rax
			rax = 0x212713CA8BC0FC71;               //mov rax, 0x212713CA8BC0FC71
			rdx *= rax;             //imul rdx, rax
			rax = 0x7B0A0E68889C8F78;               //mov rax, 0x7B0A0E68889C8F78
			rdx += rax;             //add rdx, rax
			return rdx;
		}
		case 15:
		{
			rbx = readMemory<uintptr_t>(imageBase + 0x71D924F);              //mov rbx, [0x0000000004B5C324]
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD982FE4]
			rdx += rax;             //add rdx, rax
			rdx ^= r8;              //xor rdx, r8
			rax = 0;                //and rax, 0xFFFFFFFFC0000000
			rax = _rotl64(rax, 0x10);               //rol rax, 0x10
			rax ^= rbx;             //xor rax, rbx
			rax = _byteswap_uint64(rax);            //bswap rax
			rax = readMemory<uintptr_t>(rax + 0xb);               //mov rax, [rax+0x0B]
			uintptr_t RSP_0x48;
			RSP_0x48 = 0x76F87EA0A47CB0AD;          //mov rax, 0x76F87EA0A47CB0AD : RSP+0x48
			rax *= RSP_0x48;                //imul rax, [rsp+0x48]
			rdx *= rax;             //imul rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x11;           //shr rax, 0x11
			rdx ^= rax;             //xor rdx, rax
			rax = rdx;              //mov rax, rdx
			rax >>= 0x22;           //shr rax, 0x22
			rdx ^= rax;             //xor rdx, rax
			rax = 0x660C3C0933677E41;               //mov rax, 0x660C3C0933677E41
			rdx += rax;             //add rdx, rax
			rax = imageBase;           //lea rax, [0xFFFFFFFFFD982DDC]
			rdx ^= rax;             //xor rdx, rax
			rax = 0xF87C74347306E12C;               //mov rax, 0xF87C74347306E12C
			rdx ^= rax;             //xor rdx, rax
			return rdx;
		}
		}
	}

	extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
	{
		uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, rdi = imageBase, rsi = imageBase, r8 = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase;
		rbx = index;
		rcx = rbx * 0x13C8;
		rax = 0x1DB46762E3D52EF7;               //mov rax, 0x1DB46762E3D52EF7
		rbx = imageBase;           //lea rbx, [0xFFFFFFFFFDCCACA0]
		rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
		r10 = 0x86C2D6724C0021B1;               //mov r10, 0x86C2D6724C0021B1
		rdx >>= 0xA;            //shr rdx, 0x0A
		rax = rdx * 0x2279;             //imul rax, rdx, 0x2279
		rcx -= rax;             //sub rcx, rax
		rax = 0x342C53A914269ED;                //mov rax, 0x342C53A914269ED
		r8 = rcx * 0x2279;              //imul r8, rcx, 0x2279
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rdx >>= 0x7;            //shr rdx, 0x07
		rax = rdx * 0x2741;             //imul rax, rdx, 0x2741
		r8 -= rax;              //sub r8, rax
		rax = 0x5197F7D73404147;                //mov rax, 0x5197F7D73404147
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r8;               //mov rax, r8
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x8;            //shr rax, 0x08
		rcx = rax * 0x1F6;              //imul rcx, rax, 0x1F6
		rax = 0x47AE147AE147AE15;               //mov rax, 0x47AE147AE147AE15
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r8;               //mov rax, r8
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x4;            //shr rax, 0x04
		rcx += rax;             //add rcx, rax
		rax = rcx * 0x32;               //imul rax, rcx, 0x32
		rcx = r8 * 0x34;                //imul rcx, r8, 0x34
		rcx -= rax;             //sub rcx, rax
		rax = readMemory<uint16_t>(rcx + rbx * 1 + 0x71EC670);                //movzx eax, word ptr [rcx+rbx*1+0x71EC670]
		r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
		rax = r10;              //mov rax, r10
		rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
		rax = r10;              //mov rax, r10
		rdx >>= 0xC;            //shr rdx, 0x0C
		rcx = rdx * 0x1E65;             //imul rcx, rdx, 0x1E65
		r8 -= rcx;              //sub r8, rcx
		r9 = r8 * 0x2742;               //imul r9, r8, 0x2742
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rdx >>= 0xC;            //shr rdx, 0x0C
		rax = rdx * 0x1E65;             //imul rax, rdx, 0x1E65
		r9 -= rax;              //sub r9, rax
		rax = 0x90FDBC090FDBC091;               //mov rax, 0x90FDBC090FDBC091
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = 0x29E4129E4129E413;               //mov rax, 0x29E4129E4129E413
		rdx >>= 0x7;            //shr rdx, 0x07
		rcx = rdx * 0xE2;               //imul rcx, rdx, 0xE2
		rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
		rax = r9;               //mov rax, r9
		rax -= rdx;             //sub rax, rdx
		rax >>= 0x1;            //shr rax, 0x01
		rax += rdx;             //add rax, rdx
		rax >>= 0x5;            //shr rax, 0x05
		rcx += rax;             //add rcx, rax
		rax = rcx * 0x6E;               //imul rax, rcx, 0x6E
		rcx = r9 * 0x70;                //imul rcx, r9, 0x70
		rcx -= rax;             //sub rcx, rax
		rsi = readMemory<uint16_t>(rcx + rbx * 1 + 0x71F2880);                //movsx esi, word ptr [rcx+rbx*1+0x71F2880]
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
		{
			const auto visible_list = driver::read<uint64_t>(vis_base_ptr + 0x108);
			return visible_list;
		}
	}
	return 0;
}