#include "decryption.h"
#include "globals.h"
#include "offsets.h"
#include <stdlib.h>
#include "../driver/driver.h"

extern "C" auto decryption::decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

    RBX = driver::read<uint64_t>(imageBase + 0x17CAB278);
    if (RBX == 0) {
        return 0;
    }
    RAX += 0x1B;
    // movzx eax,al
    R8 = peb; // mov r8,gs:[rax]
    RAX = RBX;
    RAX >>= 0xD;
    RDX = 0x479E361CEF408277;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0x1A;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0x34;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0x23;
    RCX = 0x0;
    RAX ^= RBX;
    RCX = _rotl64(RCX, 0x10);
    RCX ^= driver::read<uint64_t>(imageBase + 0x6B730E1);
    RAX *= RDX;
    RCX = ~RCX;
    RAX ^= R8;
    RBX = driver::read<uint64_t>(RCX + 0x11);
    RBX *= RAX;
    RBX -= R8;
    return RBX;
}

extern "C" auto decryption::decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

    RAX = driver::read<uint64_t>(clientInfo + 0x9DBD8);
    R11 = peb; // mov r11,gs:[rcx]
    R11 = ~R11;
    // test rax,rax
    // je 00007FF72A69A71Fh
    RCX = R11;
    RCX <<= 0x1A;
    RCX = _byteswap_uint64(RCX);
    RCX &= 0xF;
    // cmp rcx,0Eh
    // ja 00007FF72A69A194h
    switch (RCX) {
    case 0: {
        RBX = imageBase;
        R9 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RAX += RBX;
        RAX ^= RBX;
        RCX = RAX;
        RCX >>= 0x1F;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x3E;
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
        RAX ^= RBX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = 0xE8A1E147318EBA7D;
        RAX *= RCX;
        RAX -= R11;
        return RAX;
    }
    case 1: {
        RBX = imageBase;
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RCX = RAX;
        RCX >>= 0x23;
        RAX ^= RCX;
        RCX = 0x1B9ED60AB6993FA7;
        RAX -= RCX;
        RCX = 0x9C620774B4E705F7;
        RAX *= RCX;
        RAX -= RBX;
        RAX += 0xFFFFFFFFFFFF3114;
        RAX += R11;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = RAX;
        RCX >>= 0x9;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x12;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x24;
        RAX ^= RCX;
        RCX = R11;
        RCX -= RBX;
        RAX += RCX;
        RCX = 0xB5FA417833ADE53D;
        RAX *= RCX;
        RCX = 0x6817126348EC3B85;
        RAX -= RCX;
        return RAX;
    }
    case 2: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        R15 = imageBase + 0x41368D14;
        RCX = 0xC9125C744D87435F;
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
        RCX >>= 0x30;
        RAX ^= RCX;
        RCX = 0x4D70CABF3DA46ADB;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x11;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x22;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = R15;
        RCX = ~RCX;
        RCX += R11;
        RAX += RCX;
        RCX = R11;
        RCX -= RBX;
        RAX += RCX;
        RCX = 0xA0CF5CF6755A4F55;
        RAX *= RCX;
        RCX = 0x7FDBFFF2A6A66461;
        RAX -= RCX;
        return RAX;
    }
    case 3: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RCX = driver::read<uint64_t>(RCX + 0x13);
        RAX *= RCX;
        RAX += R11;
        RCX = RAX;
        RCX >>= 0x21;
        RAX ^= RCX;
        RAX -= RBX;
        RAX += 0xFFFFFFFFAA8A486B;
        RAX += R11;
        RAX += R11;
        RCX = 0xBD873296531E95F1;
        RAX *= RCX;
        RCX = 0x1DEA7A38C3779EB8;
        RAX += RCX;
        return RAX;
    }
    case 4: {
        R15 = imageBase + 0x2CEEBE66;
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RCX = 0x23CEE875B2435D40;
        RAX ^= RCX;
        RCX = imageBase + 0x68F3E452;
        RCX = ~RCX;
        RCX ^= R11;
        RAX -= RCX;
        RCX = 0xC89845326ACB031;
        RDX = R11;
        RAX *= RCX;
        RDX = ~RDX;
        RCX = imageBase + 0xDF83;
        RDX += RCX;
        RCX = RAX;
        RCX >>= 0x23;
        RDX ^= RCX;
        RAX ^= RDX;
        RCX = imageBase + 0x251630A8;
        RCX = ~RCX;
        RCX ^= R11;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = R15;
        RCX -= R11;
        RAX += RCX;
        return RAX;
    }
    case 5: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RAX -= R11;
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
        RCX = 0xB8959A23483015F9;
        RAX *= RCX;
        RAX -= R11;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = RAX;
        RDX ^= R10;
        RCX >>= 0x25;
        RDX = ~RDX;
        RCX ^= RAX;
        RCX += R11;
        RAX = driver::read<uint64_t>(RDX + 0x13);
        RAX *= RCX;
        RCX = 0x92D44ACC7EDF206F;
        RAX *= RCX;
        return RAX;
    }
    case 6: {
        R9 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        RAX -= R11;
        RCX = 0xF0412FDB56660397;
        RAX *= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RCX = driver::read<uint64_t>(RCX + 0x13);
        RAX *= RCX;
        RAX ^= RBX;
        RCX = RAX;
        RCX >>= 0xB;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x16;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2C;
        RCX ^= RAX;
        RAX = 0x56C31B8264180F4C;
        RAX += RCX;
        RAX += RBX;
        return RAX;
    }
    case 7: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        R15 = imageBase + 0xB203;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = RAX;
        RDX ^= R10;
        RCX -= RBX;
        RDX = ~RDX;
        RAX = driver::read<uint64_t>(RDX + 0x13);
        RAX *= RCX;
        RCX = R11;
        RCX = ~RCX;
        RCX *= R15;
        RAX += RCX;
        RCX = 0xBE5CC53357A67EBB;
        RAX *= RCX;
        RCX = 0xA0B7A5D2DA5E848B;
        RAX *= RCX;
        RCX = RAX;
        RCX >>= 0x1D;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x3A;
        RAX ^= RCX;
        RAX += R11;
        RCX = 0x449CC9D0532F7491;
        RAX *= RCX;
        return RAX;
    }
    case 8: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        R15 = imageBase + 0x119C;
        RCX = R11 + RAX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RDX ^= R10;
        RDX = ~RDX;
        RAX = driver::read<uint64_t>(RDX + 0x13);
        RAX *= RCX;
        RCX = 0x83F4AD112CC9B719;
        RAX *= RCX;
        RCX = R11;
        RCX *= R15;
        RAX -= RCX;
        RCX = 0xDAF3E1378D432384;
        RAX ^= RCX;
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
        RCX = 0xD6158761DA3B2BD6;
        RAX ^= RCX;
        RCX = R11;
        RCX = ~RCX;
        RAX += RCX;
        RAX -= RBX;
        RAX -= 0x9E55;
        return RAX;
    }
    case 9: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        RCX = RBX + 0x7CB07693;
        RCX += R11;
        RAX ^= RCX;
        RCX = 0xB04781CA9C29E4D9;
        RAX *= RCX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = imageBase + 0x3E3761A0;
        RDX ^= R10;
        RCX -= R11;
        RCX ^= RAX;
        RDX = ~RDX;
        RAX = driver::read<uint64_t>(RDX + 0x13);
        RAX *= RCX;
        RCX = RBX + 0x3283;
        RCX += R11;
        RCX ^= RAX;
        RAX = 0x47F93DC3CBA1E12A;
        RCX -= RAX;
        RAX = RCX;
        RAX >>= 0x18;
        RCX ^= RAX;
        RAX = RCX;
        RAX >>= 0x30;
        RAX ^= RCX;
        RCX = 0xC8F4A762B4448EAC;
        RAX ^= RCX;
        return RAX;
    }
    case 10: {
        uint64_t RBP_NEG_0x80 = imageBase;
        RBX = imageBase;
        RCX = 0x9CD7D56552083751;
        RBP_NEG_0x80 = RCX; // mov [rbp-80h],rcx
        R9 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RCX = 0x20425EADB71544B2;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x3;
        RAX ^= RCX;
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
        RCX >>= 0x14;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x28;
        RAX ^= RCX;
        RCX = 0xD09958F1FF08D975;
        RAX *= RCX;
        RAX ^= R11;
        RAX -= R11;
        RAX -= RBX;
        RAX -= 0x2CB4;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RCX = driver::read<uint64_t>(RCX + 0x13);
        RCX *= RBP_NEG_0x80; // imul rcx,[rbp-80h]
        RAX *= RCX;
        return RAX;
    }
    case 11: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        RDX = imageBase + 0x4218;
        RCX = RAX;
        RCX >>= 0xD;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x1A;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x34;
        RAX ^= RCX;
        RAX += R11;
        RAX += RBX;
        RCX = R11;
        RCX *= RDX;
        RAX ^= RCX;
        RCX = 0xE932F6990053C3B5;
        RAX *= RCX;
        RCX = 0x373D1D8C794B4406;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x11;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x22;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        return RAX;
    }
    case 12: {
        RBX = imageBase;
        R14 = imageBase + 0x36D748DA;
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RAX ^= RBX;
        RCX = 0x7197F93DDB94A6BF;
        RAX -= RCX;
        RCX = R11;
        RCX *= R14;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x16;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2C;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x22;
        RAX ^= RCX;
        RCX = 0xB0EC95D58D0DF71F;
        RAX *= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = 0x39316699842F0172;
        RAX += RCX;
        return RAX;
    }
    case 13: {
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RBX = imageBase;
        RAX ^= RBX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = RAX;
        RDX ^= R10;
        RAX = 0xAEB1E95926989E4E;
        RDX = ~RDX;
        RCX ^= RAX;
        RAX = driver::read<uint64_t>(RDX + 0x13);
        RAX *= RCX;
        RCX = RAX;
        RCX >>= 0x1D;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x3A;
        RAX ^= RCX;
        RCX = 0xDA0029A702EA0593;
        RAX ^= RCX;
        RAX += RBX;
        RCX = RAX;
        RCX >>= 0x10;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x20;
        RAX ^= RCX;
        RCX = 0xC4B0A728106DA019;
        RAX *= RCX;
        return RAX;
    }
    case 14: {
        R14 = imageBase + 0x7880C2C9;
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RAX ^= R11;
        RCX = RAX;
        RCX >>= 0xE;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x1C;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x38;
        RAX ^= RCX;
        RDX = R14;
        RDX = ~RDX;
        RCX = R11;
        RCX = ~RCX;
        RAX += RCX;
        RCX = 0xED2D161C9A9747F1;
        RAX += RDX;
        RAX ^= R11;
        RAX ^= RCX;
        RCX = 0xB238EA22EA6F0EDD;
        RAX *= RCX;
        RCX = 0x9919244B4997D2CF;
        RAX *= RCX;
        return RAX;
    }
    case 15: {
        RDX = imageBase + 0x20770946;
        RBX = imageBase;
        R12 = imageBase + 0x712BD440;
        R10 = driver::read<uint64_t>(imageBase + 0x6B730FB);
        RCX = imageBase + 0x2B6F;
        RCX = ~RCX;
        RCX ^= R11;
        RAX += RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0x13);
        RCX = RAX;
        RCX >>= 0xD;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x1A;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x34;
        RAX ^= RCX;
        RCX = R11;
        RCX = ~RCX;
        RCX ^= R12;
        RAX -= RCX;
        RCX = 0x258512007E653223;
        RAX *= RCX;
        RCX = R11;
        RCX *= RDX;
        RAX -= RCX;
        RCX = 0x1F5E7A45C405C65D;
        RAX ^= RCX;
        RAX -= RBX;
        RAX += 0xFFFFFFFFFFFF6C37;
        RAX += R11;
        return RAX;
    }
    }
}

struct ref_def_key
{
	int ref0, ref1, ref2;
};

uintptr_t decryption::get_ref_def(const uintptr_t ref_def_ptr)
{
	const auto crypt = driver::read<ref_def_key>(globals::base + ref_def_ptr);

	DWORD lower = crypt.ref0 ^ (crypt.ref2 ^ (uint64_t)(globals::base + ref_def_ptr)) * ((crypt.ref2 ^ (uint64_t)(globals::base + ref_def_ptr)) + 2);
	DWORD upper = crypt.ref1 ^ (crypt.ref2 ^ (uint64_t)(globals::base + ref_def_ptr + 0x4)) * ((crypt.ref2 ^ (uint64_t)(globals::base + ref_def_ptr + 0x4)) + 2);

	return (uint64_t)upper << 32 | lower;
}