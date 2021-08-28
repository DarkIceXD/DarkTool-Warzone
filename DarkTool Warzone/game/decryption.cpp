#include "decryption.h"
#include "globals.h"
#include "offsets.h"
#include <stdlib.h>
#include "../driver/driver.h"

extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

    RBX = driver::read<uint64_t>(imageBase + 0x179302F8);
    if (RBX == 0) {
        return 0;
    }
    uint64_t RSP_0x50 = imageBase;
    RSP_0x50 = 0x18; // mov byte ptr [rsp+50h],18h
    // movzx eax,byte ptr [rsp+50h]
    R8 = imageBase;
    RAX = _rotr64(RAX, 0x3E);
    // movzx eax,al
    RCX = peb; // mov rcx,gs:[rax]
    RCX = ~RCX;
    RDX = 0xFE6FC31D37029CCB;
    RAX = 0x0;
    RAX = _rotl64(RAX, 0x10);
    RAX ^= driver::read<uint64_t>(imageBase + 0x67FB0FC);
    RAX = ~RAX;
    RAX = driver::read<uint64_t>(RAX + 0x9);
    RAX *= RDX;
    RBX *= RAX;
    RAX = RBX;
    RAX >>= 0x7;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0xE;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0x1C;
    RBX ^= RAX;
    RAX = RBX;
    RAX >>= 0x38;
    RBX ^= RAX;
    RAX = 0xD5864B9ED1AC7F75;
    RBX -= R8;
    RBX *= RAX;
    RAX = imageBase + 0xFE2C;
    RCX *= RAX;
    RBX -= RCX;
    return RBX;
}

extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

    RAX = driver::read<uint64_t>(clientInfo + 0x9DC38);
    R11 = peb; // mov r11,gs:[rcx]
    // test rax,rax
    // je 00007FF794122BE5h
    RCX = R11;
    RCX >>= 0x17;
    RCX &= 0xF;
    // cmp rcx,0Eh
    // ja 00007FF794122689h
    switch (RCX) {
    case 0: {
        RSI = imageBase + 0x26BD;
        R9 = driver::read<uint64_t>(imageBase + 0x67FB135);
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
        RAX -= R11;
        RAX += RSI;
        RCX = 0x3577A1A3C799F24;
        RAX += RCX;
        RCX = RAX;
        RCX >>= 0x15;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2A;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RCX = driver::read<uint64_t>(RCX + 0xF);
        RAX *= RCX;
        RCX = 0x3ECE4BA3EAB88BC1;
        RAX *= RCX;
        RAX += R11;
        return RAX;
    }
    case 1: {
        R15 = imageBase + 0x3C65C721;
        R14 = imageBase + 0x566326E9;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RDX = RAX;
        RCX = imageBase + 0x741B;
        RAX = R11;
        RAX *= RCX;
        RCX = 0x1AB412D1A8B3F1E;
        RAX ^= RDX;
        RAX ^= R11;
        RAX ^= R15;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x12;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x24;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RDX = R11;
        RDX = ~RDX;
        RDX ^= R14;
        RCX = RAX;
        RAX = 0x3D285928C2BA6D69;
        RAX *= RCX;
        RAX += RDX;
        RCX = 0x87349DA53452C668;
        RAX ^= RCX;
        return RAX;
    }
    case 2: {
        R14 = imageBase + 0x5551D555;
        R9 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RCX = RAX;
        RCX >>= 0x1A;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x34;
        RCX ^= R11;
        RAX ^= RCX;
        RSI = 0xF083AE4EFC5CF8D9;
        RCX = R11;
        RCX *= R14;
        RCX += RSI;
        RAX += RCX;
        RCX = 0x495B672DDFF4C79A;
        RAX ^= RCX;
        RCX = 0x21BEA6484094EE31;
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
        return RAX;
    }
    case 3: {
        R15 = imageBase + 0x5483A609;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RCX = R11;
        RCX = ~RCX;
        RAX ^= RCX;
        RCX = imageBase;
        RAX ^= R15;
        RAX -= RCX;
        RCX = 0x6DB09640D873D9E1;
        RAX *= RCX;
        RCX = imageBase;
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
        RCX = imageBase;
        RAX -= RCX;
        RCX = 0x3139D1EC9F95155B;
        RAX -= RCX;
        return RAX;
    }
    case 4: {
        R14 = imageBase + 0x29F61CB7;
        R9 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = R14;
        RCX = ~RCX;
        RCX *= R11;
        RAX ^= RCX;
        RCX = 0x3B501AF25251E94A;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x20;
        RAX ^= RCX;
        RCX = 0x51AEA3739FFAD47D;
        RAX *= RCX;
        RCX = imageBase + 0x35C7D984;
        RAX += R11;
        RAX += RCX;
        RCX = imageBase + 0xBF03;
        RCX -= R11;
        RAX += RCX;
        RCX = 0xA39130DB0F4A771D;
        RAX *= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R9;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        return RAX;
    }
    case 5: {
        R15 = imageBase + 0xBFB5;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RDX = imageBase + 0x4717;
        RCX = R15;
        RCX -= R11;
        RAX ^= RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RCX = R11;
        RCX ^= RDX;
        RAX -= RCX;
        RAX -= R11;
        RCX = 0x488AA665612944F5;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x15;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2A;
        RAX ^= RCX;
        RCX = 0xC4FB88A311EC464E;
        RAX ^= RCX;
        RCX = 0x585BB4C4771BF83D;
        RAX *= RCX;
        return RAX;
    }
    case 6: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        R14 = imageBase + 0x2EB0;
        RCX = imageBase;
        RAX += RCX;
        RCX = 0x4FDE02BB52F7F8AE;
        RAX -= RCX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = R14;
        RCX = ~RCX;
        RDX ^= R10;
        RCX ^= R11;
        RDX = ~RDX;
        RCX ^= RAX;
        RAX = driver::read<uint64_t>(RDX + 0xF);
        RAX *= RCX;
        RCX = 0x565467D6B529281D;
        RAX *= RCX;
        RCX = imageBase;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x28;
        RAX ^= RCX;
        RCX = 0xB4852AEC637CFA;
        RAX -= RCX;
        return RAX;
    }
    case 7: {
        uint64_t RSP_0x48 = imageBase;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = imageBase + 0xF209;
        RSP_0x48 = RCX; // mov [rsp+48h],rcx
        R15 = imageBase + 0x26FA8C56;
        RAX -= R11;
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
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RAX += R11;
        RCX = 0xEE8930C356DAC66D;
        RAX *= RCX;
        RAX += R11;
        RDX = R15;
        RCX = R11;
        RCX = ~RCX;
        RDX = ~RDX;
        RCX ^= RSP_0x48; // xor rcx,[rsp+48h]
        RDX *= R11;
        RDX -= RCX;
        RAX += RDX;
        return RAX;
    }
    case 8: {
        R15 = imageBase + 0x6104F5D0;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = R15;
        RCX = ~RCX;
        RCX ^= R11;
        RAX -= RCX;
        RCX = 0xE31B9303B67241B3;
        RAX *= RCX;
        RCX = 0x407DA7F5ABBA0B35;
        RAX ^= RCX;
        RCX = 0x16209D16F22F9A2A;
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
        RCX >>= 0x1C;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x38;
        RAX ^= RCX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RDX ^= R10;
        RDX = ~RDX;
        RDX = driver::read<uint64_t>(RDX + 0xF);
        RDX *= RAX;
        RAX = imageBase + 0xB894;
        RAX = ~RAX;
        RAX *= R11;
        RAX += RDX;
        return RAX;
    }
    case 9: {
        R14 = imageBase + 0x3AC6;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = imageBase;
        RCX += 0x7CD1465B;
        RCX += R11;
        RAX += RCX;
        RCX = RAX;
        RCX >>= 0x27;
        RAX ^= RCX;
        RCX = imageBase;
        RAX ^= RCX;
        RCX = 0x67B1B4BD21BFB786;
        RAX ^= RCX;
        RAX ^= R11;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RCX = 0x6B16A8EF07BB817F;
        RAX *= RCX;
        RDX = R11;
        RDX = ~RDX;
        RCX = R14;
        RCX = ~RCX;
        RDX += RCX;
        RAX ^= RDX;
        return RAX;
    }
    case 10: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RSI = imageBase + 0x6ADA;
        RCX = 0x52F34A9EC14971D8;
        RAX += RCX;
        RCX = RAX;
        RCX >>= 0x16;
        RAX ^= RCX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RCX = RAX;
        RDX ^= R10;
        RCX >>= 0x2C;
        RDX = ~RDX;
        RCX ^= RAX;
        RAX = driver::read<uint64_t>(RDX + 0xF);
        RAX *= RCX;
        RCX = 0xD61F39EC4C4A3E77;
        RAX *= RCX;
        RCX = imageBase + 0xF60B;
        RCX = ~RCX;
        RAX += RCX;
        RCX = imageBase + 0x2BC6BF05;
        RAX += RCX;
        RCX = R11;
        RCX ^= RSI;
        RAX += RCX;
        RCX = imageBase;
        RAX ^= RCX;
        return RAX;
    }
    case 11: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RDX = imageBase + 0x3599D644;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        RAX ^= R11;
        RAX ^= RDX;
        RCX = RAX;
        RCX >>= 0x19;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x32;
        RAX ^= RCX;
        RCX = imageBase + 0xE81F;
        RCX = ~RCX;
        RCX *= R11;
        RAX += RCX;
        RCX = 0x5CE4A91B453CA2B5;
        RAX *= RCX;
        RCX = 0xFBD301072DA48C49;
        RAX *= RCX;
        RCX = 0x6D3E2BBCB0B5BAFE;
        RAX += RCX;
        return RAX;
    }
    case 12: {
        R14 = imageBase + 0x3C18896C;
        R15 = imageBase + 0x7358;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RDX ^= R10;
        RCX = imageBase + 0x37182832;
        RCX = ~RCX;
        RDX = ~RDX;
        RCX ^= R11;
        RDX = driver::read<uint64_t>(RDX + 0xF);
        RAX *= RDX;
        RAX -= RCX;
        RCX = R15;
        RCX = ~RCX;
        RCX += R11;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x1C;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x38;
        RAX ^= RCX;
        RCX = R11;
        RCX ^= R14;
        RAX -= RCX;
        RCX = 0x5A75353690BF4BB6;
        RAX -= RCX;
        RCX = 0x14B683D257A0AC05;
        RAX -= RCX;
        RCX = 0xCD3F082CCF689C3B;
        RAX *= RCX;
        return RAX;
    }
    case 13: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = RAX;
        RCX >>= 0x10;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x20;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x28;
        RAX ^= RCX;
        RCX = imageBase + 0x3BF05E93;
        RAX += R11;
        RAX += RCX;
        RCX = 0x8E178B4D1FA76B53;
        RAX ^= RCX;
        RCX = 0x6E360574F4F05AE3;
        RAX -= RCX;
        RCX = RAX;
        RCX >>= 0x17;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2E;
        RDX = 0x0;
        RCX ^= RAX;
        RDX = _rotl64(RDX, 0x10);
        RDX ^= R10;
        RDX = ~RDX;
        RAX = driver::read<uint64_t>(RDX + 0xF);
        RAX *= RCX;
        RCX = 0xA2BA560E0DCA4EE3;
        RAX *= RCX;
        return RAX;
    }
    case 14: {
        uint64_t RSP_0x70 = imageBase;
        RCX = imageBase + 0x1228DA68;
        RSP_0x70 = RCX; // mov [rsp+70h],rcx
        RDX = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = RAX;
        RCX >>= 0x1D;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x3A;
        RAX ^= RCX;
        RCX = imageBase;
        RCX += 0x759AA3A7;
        RCX += R11;
        RAX += RCX;
        RCX = 0x7C95F63657C1D725;
        RAX *= RCX;
        RCX = 0xE86C0C7105CDFF33;
        RAX *= RCX;
        R10 = 0xD3FE55DB3D4FC3C5;
        RCX = R11;
        RCX *= RSP_0x70; // imul rcx,[rsp+70h]
        RCX += R10;
        RAX += RCX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= RDX;
        RCX = ~RCX;
        RAX *= driver::read<uint64_t>(RCX + 0xF);
        return RAX;
    }
    case 15: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB135);
        RCX = imageBase;
        RAX -= RCX;
        RCX = 0xBB37BFCF3BDA3171;
        RAX *= RCX;
        RCX = RAX;
        RCX >>= 0xA;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x14;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x28;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0xB;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x16;
        RAX ^= RCX;
        RCX = RAX;
        RCX >>= 0x2C;
        RCX ^= RAX;
        RDX = 0x0;
        RDX = _rotl64(RDX, 0x10);
        RDX ^= R10;
        RDX = ~RDX;
        RAX = driver::read<uint64_t>(RDX + 0xF);
        RAX *= RCX;
        RCX = 0x6DAE9526BEBF03B9;
        RAX ^= RCX;
        RCX = 0x4408D5B3AA254ED7;
        RAX *= RCX;
        RAX -= R11;
        return RAX;
    }
    }
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