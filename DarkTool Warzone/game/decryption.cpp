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

extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

    R8 = driver::read<uint64_t>(imageBase + 0x15C1FC98);
    if (R8 == 0) {
        return 0;
    }
    RBX = peb; // mov rbx,gs:[rax]
    // test r8,r8
    // je 00007FF79426CEB2h
    RAX = RBX;
    RAX >>= 0x1C;
    RAX &= 0xF;
    // cmp rax,0Eh
    // ja 00007FF79426C9D7h
    switch (RAX) {
    case 0: {
        // push rbx
        // pushfq
        // pop rbx
        // popfq
        // pop rbx
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = 0xD400C48A96FD460B;
        R8 *= RAX;
        R8 ^= RBX;
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R10;
        RAX = _byteswap_uint64(RAX);
        R8 *= driver::read<uint64_t>(RAX + 0x11);
        RAX = R8;
        RAX >>= 0x17;
        R8 ^= RAX;
        RCX = R8;
        RCX >>= 0x2E;
        RCX ^= R8;
        R8 = imageBase + 0x558FDA8C;
        RAX = RBX;
        RAX = ~RAX;
        R8 *= RAX;
        RAX = imageBase + 0x5E7CD6BA;
        R8 += RCX;
        R8 += RAX;
        RAX = imageBase;
        R8 -= RAX;
        return R8;
    }
    case 1: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = 0x591390EF81A13BC6;
        R8 ^= RAX;
        RAX = 0xCC16DF6688041E13;
        R8 *= RAX;
        RAX = R8;
        RAX >>= 0x12;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x24;
        R8 ^= RAX;
        RAX = imageBase;
        R8 ^= RAX;
        RAX = 0x16F30E650A04CB81;
        R8 *= RAX;
        RCX = 0x0;
        RAX = R8;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RAX >>= 0x21;
        RAX ^= R8;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        R8 -= RBX;
        return R8;
    }
    case 2: {
        uint64_t RSP_0x78 = imageBase;
        // push rax
        // pushfq
        // pop rax
        // popfq
        // pop rax
        RCX = imageBase + 0x6C98B583;
        RSP_0x78 = RCX; // mov [rsp+78h],rcx
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = RBX;
        RAX *= RSP_0x78; // imul rax,[rsp+78h]
        R8 -= RAX;
        RCX = 0x0;
        RAX = R8;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        R8 = 0x2629738A1FBB3CBC;
        RAX ^= R8;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = imageBase;
        R8 -= RAX;
        RAX = 0x18F2E10705C88997;
        R8 += RAX;
        RAX = R8;
        RAX >>= 0x9;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x12;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x24;
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
        RAX = 0x790DC5F9E77DB383;
        R8 *= RAX;
        return R8;
    }
    case 3: {
        uint64_t RBP_NEG_0x38 = imageBase;
        R9 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
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
        RAX = 0x4362551BD1A44749;
        R8 *= RAX;
        RAX = 0x3AC41A89C131E9C3;
        R8 += RAX;
        RAX = R8;
        RAX >>= 0x1F;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x3E;
        R8 ^= RAX;
        RAX = RBX;
        RAX -= RBP_NEG_0x38; // sub rax,[rbp-38h]
        RAX -= 0x2987173F;
        R8 ^= RAX;
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R9;
        RAX = _byteswap_uint64(RAX);
        R8 *= driver::read<uint64_t>(RAX + 0x11);
        RAX = 0x6CF642E511B85B3B;
        R8 *= RAX;
        RAX = R8;
        RAX >>= 0x12;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x24;
        R8 ^= RAX;
        return R8;
    }
    case 4: {
        RCX = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = R8;
        RAX >>= 0x24;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x19;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x32;
        R8 ^= RAX;
        RAX = 0x3AE6C8EA23D7CAA9;
        R8 -= RAX;
        RAX = imageBase;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x7;
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
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= RCX;
        RAX = _byteswap_uint64(RAX);
        R8 *= driver::read<uint64_t>(RAX + 0x11);
        RAX = 0xE1ABE343F54D02D3;
        R8 *= RAX;
        RAX = imageBase + 0x8015;
        RAX = ~RAX;
        RAX ^= RBX;
        R8 ^= RAX;
        return R8;
    }
    case 5: {
        uint64_t RBP_NEG_0x40 = imageBase;
        uint64_t RBP_NEG_0x68 = imageBase;
        // pushfq
        // push rbx
        // pop rbx
        // pop rbx
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = imageBase + 0xCB49;
        RBP_NEG_0x68 = RAX; // mov [rbp-68h],rax
        RAX = imageBase + 0x17A7AB8F;
        RBP_NEG_0x40 = RAX; // mov [rbp-40h],rax
        RAX = R8;
        RAX >>= 0xC;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x18;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x30;
        R8 ^= RAX;
        RAX = RBX;
        RAX ^= RBP_NEG_0x68; // xor rax,[rbp-68h]
        R8 += RAX;
        RAX = 0x9A5C4FFF10BB23F;
        R8 *= RAX;
        RAX = imageBase;
        RAX += 0x7198;
        RAX += RBX;
        R8 ^= RAX;
        RAX = 0xC07464ABE121CBB2;
        R8 ^= RAX;
        RAX = RBX;
        RCX = 0x0;
        RAX = ~RAX;
        RAX ^= RBP_NEG_0x40; // xor rax,[rbp-40h]
        RAX += R8;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = 0xC9F41707BF09F16B;
        R8 *= RAX;
        return R8;
    }
    case 6: {
        R11 = imageBase + 0x3BAA;
        R9 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R9;
        RAX = _byteswap_uint64(RAX);
        RAX = driver::read<uint64_t>(RAX + 0x11);
        R8 *= RAX;
        RAX = 0xAF99A13EE9F4F5E7;
        R8 *= RAX;
        RAX = imageBase;
        R8 += RAX;
        RAX = 0x9FF32413B72D07C0;
        R8 ^= RAX;
        RAX = R11;
        RAX = ~RAX;
        RAX *= RBX;
        R8 ^= RAX;
        RAX = 0xF2CA424F0A6D19A7;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x27;
        R8 ^= RAX;
        RAX = imageBase;
        R8 -= RAX;
        return R8;
    }
    case 7: {
        uint64_t RBP_NEG_0x70 = imageBase;
        // push rbx
        // pushfq
        // pop rbx
        // popfq
        // pop rbx
        RCX = imageBase + 0xCFDE;
        RBP_NEG_0x70 = RCX; // mov [rbp-70h],rcx
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = R8;
        RAX >>= 0x26;
        R8 ^= RAX;
        RAX = imageBase;
        R8 -= RAX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RAX = RBX;
        RAX *= RBP_NEG_0x70; // imul rax,[rbp-70h]
        RCX = _byteswap_uint64(RCX);
        R8 -= RAX;
        RAX = 0x49E8B26B7A37ACB;
        RAX *= R8;
        R8 = 0x20AB3E8CAD4A4075;
        RAX += R8;
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = imageBase;
        R8 -= RAX;
        RAX = 0x5E2BF7651FDE63D7;
        R8 -= RAX;
        return R8;
    }
    case 8: {
        R11 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RCX = RBX;
        RCX = ~RCX;
        RDX = 0x0;
        RAX = imageBase + 0x81F2;
        RDX = _rotl64(RDX, 0x10);
        RAX = ~RAX;
        RCX *= RAX;
        RDX ^= R11;
        RCX += R8;
        RDX = _byteswap_uint64(RDX);
        R8 = driver::read<uint64_t>(RDX + 0x11);
        R8 *= RCX;
        RDX = imageBase + 0x30BFADDC;
        RAX = 0xEF32FB22BA05068D;
        R8 *= RAX;
        RAX = RBX;
        RAX *= RDX;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x1D;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x3A;
        R8 ^= RAX;
        RAX = 0x36823D1F32D5C0C9;
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
        RAX = 0xE8ABE8747885683F;
        R8 ^= RAX;
        return R8;
    }
    case 9: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RCX = 0x0;
        RAX = imageBase + 0x9CBF;
        RCX = _rotl64(RCX, 0x10);
        RAX -= RBX;
        RAX ^= R8;
        RCX ^= R10;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = 0xCB29257956CB181C;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x18;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x30;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0xB;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x16;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x2C;
        RAX ^= RBX;
        R8 ^= RAX;
        RAX = 0x7A5E53429AB1ADCF;
        R8 *= RAX;
        RAX = imageBase + 0x1C9;
        RAX = ~RAX;
        RAX += RBX;
        R8 ^= RAX;
        return R8;
    }
    case 10: {
        uint64_t RBP_NEG_0x38 = imageBase;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = R8;
        RAX >>= 0x5;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0xA;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x14;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x28;
        R8 ^= RAX;
        RCX = 0x0;
        RAX = RBX;
        RAX = ~RAX;
        RCX = _rotl64(RCX, 0x10);
        RAX -= RBP_NEG_0x38; // sub rax,[rbp-38h]
        RCX ^= R10;
        RAX += 0xFFFFFFFFFFFF31FA;
        RAX += R8;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = 0x590B701CB12E47F0;
        R8 -= RAX;
        RAX = 0x63C8FF0DB78B46F7;
        R8 ^= RAX;
        RAX = imageBase;
        R8 -= RAX;
        R8 += 0xFFFFFFFFFFFF8925;
        R8 += RBX;
        RAX = R8;
        RAX >>= 0x22;
        R8 ^= RAX;
        RAX = 0xFAFEBF069D0D69D;
        R8 *= RAX;
        return R8;
    }
    case 11: {
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        R8 ^= RBX;
        RAX = 0xA49C7A33AB5E8F89;
        R8 *= RAX;
        RAX = R8 + RBX;
        R8 = 0x2BE4C9B9AD37236A;
        RAX += R8;
        R8 = imageBase;
        R8 += RAX;
        RAX = 0xE7F1DC6FBEF3C745;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x28;
        R8 ^= RAX;
        RAX = imageBase;
        R8 -= RAX;
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R10;
        RAX = _byteswap_uint64(RAX);
        R8 *= driver::read<uint64_t>(RAX + 0x11);
        return R8;
    }
    case 12: {
        uint64_t RBP_NEG_0x38 = imageBase;
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RAX = R8;
        RCX ^= R10;
        R8 = imageBase;
        RAX -= R8;
        RCX = _byteswap_uint64(RCX);
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RCX = imageBase + 0x4122C852;
        RAX = RBX;
        RAX = ~RAX;
        R8 ^= RAX;
        R8 ^= RCX;
        RAX = 0x9371937110C3E571;
        R8 *= RAX;
        RAX = 0x4D6579411936D45B;
        R8 += RAX;
        RAX = RBX;
        RAX = ~RAX;
        RAX -= RBP_NEG_0x38; // sub rax,[rbp-38h]
        RAX += 0xFFFFFFFFB91CA8FA;
        R8 += RAX;
        RAX = R8;
        RAX >>= 0x1B;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x36;
        R8 ^= RAX;
        R8 ^= RBX;
        return R8;
    }
    case 13: {
        R9 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = R8;
        RAX >>= 0xF;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x1E;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x3C;
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
        RAX = R8;
        RAX >>= 0x25;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x1A;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x34;
        R8 ^= RAX;
        RAX = 0x9A89C5674FFB7774;
        R8 ^= RAX;
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R9;
        RAX = _byteswap_uint64(RAX);
        RAX = driver::read<uint64_t>(RAX + 0x11);
        R8 *= RAX;
        RAX = 0x91F3B14EA4FDE6D1;
        R8 *= RAX;
        RAX = 0xA4CB864A0E00D31A;
        R8 ^= RAX;
        return R8;
    }
    case 14: {
        uint64_t RBP_NEG_0x78 = imageBase;
        // pushfq
        // push rbx
        // pop rbx
        // pop rbx
        RCX = imageBase + 0x461ECA5D;
        RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
        R10 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = imageBase;
        R8 -= RAX;
        R8 += 0xFFFFFFFFFFFF7BD5;
        R8 += RBX;
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
        RAX = R8;
        RAX >>= 0x22;
        R8 ^= RAX;
        RCX = 0x0;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= R10;
        RAX = RBX;
        RAX *= RBP_NEG_0x78; // imul rax,[rbp-78h]
        RCX = _byteswap_uint64(RCX);
        RAX += R8;
        R8 = driver::read<uint64_t>(RCX + 0x11);
        R8 *= RAX;
        RAX = 0x63B31A1DCE69F77D;
        R8 *= RAX;
        RAX = 0x343FE360E5370467;
        R8 += RAX;
        RAX = 0xA12AF9348C1AD707;
        R8 *= RAX;
        return R8;
    }
    case 15: {
        R9 = driver::read<uint64_t>(imageBase + 0x67FB1F9);
        RAX = imageBase;
        RAX += 0xEF9A;
        RAX += RBX;
        R8 ^= RAX;
        RAX = 0x3231A3180BAD9379;
        R8 -= RAX;
        RAX = 0x0;
        RAX = _rotl64(RAX, 0x10);
        RAX ^= R9;
        RAX = _byteswap_uint64(RAX);
        R8 *= driver::read<uint64_t>(RAX + 0x11);
        R8 ^= RBX;
        RAX = 0xF8BCB6CC9131BD90;
        R8 ^= RAX;
        RAX = 0x87C739185401C56F;
        R8 *= RAX;
        RAX = R8;
        RAX >>= 0x1F;
        R8 ^= RAX;
        RAX = R8;
        RAX >>= 0x3E;
        R8 ^= RAX;
        R8 ^= RBX;
        return R8;
    }
    }
}

extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
{
    uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

    RBX = index;
    RCX = RBX * 0x13C8;
    RAX = 0x9C92F0E69464C391;
    R11 = imageBase;
    RAX = _umul128(RAX, RCX, &RDX);
    R10 = 0x1CA24BE426242F17;
    RDX >>= 0xC;
    RAX = RDX * 0x1A29;
    RCX -= RAX;
    RAX = 0x16CE99808323F2A3;
    R8 = RCX * 0x1A29;
    RAX = _umul128(RAX, R8, &RDX);
    RDX >>= 0xA;
    RAX = RDX * 0x2CE6;
    R8 -= RAX;
    RAX = 0x8618618618618619;
    RAX = _umul128(RAX, R8, &RDX);
    RAX = R8;
    RAX -= RDX;
    RAX >>= 0x1;
    RAX += RDX;
    RAX >>= 0x4;
    RCX = RAX * 0x15;
    RAX = 0x3E22CBCE4A9027C5;
    RAX = _umul128(RAX, R8, &RDX);
    RAX = R8;
    RAX -= RDX;
    RAX >>= 0x1;
    RAX += RDX;
    RAX >>= 0x9;
    RCX += RAX;
    RAX = RCX * 0x670;
    RCX = R8 * 0x672;
    RCX -= RAX;
    RAX = driver::read<uint16_t>(RCX + R11 + 0x68086E0);
    R8 = RAX * 0x13C8;
    RAX = R10;
    RAX = _umul128(RAX, R8, &RDX);
    RAX = R10;
    RDX >>= 0xA;
    RCX = RDX * 0x23C3;
    R8 -= RCX;
    R9 = R8 * 0x36D0;
    RAX = _umul128(RAX, R9, &RDX);
    RDX >>= 0xA;
    RAX = RDX * 0x23C3;
    R9 -= RAX;
    RAX = 0x95024AB90638887F;
    RAX = _umul128(RAX, R9, &RDX);
    RCX = R9;
    R9 &= 0x1;
    RDX >>= 0xC;
    RAX = RDX * 0x1B7D;
    RCX -= RAX;
    RAX = R9 + RCX * 2;
    RSI = driver::read<uint16_t>(R11 + RAX * 2 + 0x6810E10);
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