#include "decryption.h"
#include "globals.h"
#include "offsets.h"
#include <stdlib.h>
#include "../driver/driver.h"
#define readMemory driver::read

namespace decryption {
    extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

        RBX = readMemory<uint64_t>(imageBase + 0x179CD278);
        if (RBX == 0) {
            return 0;
        }
        uint64_t RSP_0x60 = imageBase;
        RSP_0x60 = 0xC; // mov byte ptr [rsp+60h],0Ch
        // movzx eax,byte ptr [rsp+60h]
        RAX = _rotr64(RAX, 0x6D);
        // movzx eax,al
        RDX = peb; // mov rdx,gs:[rax]
        R8 = imageBase + 0xB874;
        RCX = 0x0;
        RAX = RDX;
        RAX ^= RBX;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= readMemory<uint64_t>(imageBase + 0x6897101);
        RAX ^= R8;
        RAX -= RDX;
        RCX = ~RCX;
        RBX = readMemory<uint64_t>(RCX + 0x17);
        RBX *= RAX;
        RAX = 0xA33FDB4AB6B81665;
        RBX *= RAX;
        RAX = RBX;
        RAX >>= 0x23;
        RBX ^= RAX;
        RAX = RBX;
        RAX >>= 0x27;
        RBX ^= RAX;
        return RBX;
    }

    extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RAX = readMemory<uint64_t>(clientInfo + 0x9DBF8);
        RBX = peb; // mov rbx,gs:[rcx]
        // test rax,rax
        // je 00007FF618633487h
        RCX = RBX;
        RCX = _rotr64(RCX, 0xD);
        RCX &= 0xF;
        // cmp rcx,0Eh
        // ja 00007FF618632F34h
        switch (RCX) {
        case 0: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = 0x661DA26E09C6C40B;
            RAX *= RCX;
            RAX += RBX;
            RCX = 0x3C37C578B00F8753;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x15;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2A;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x17;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2E;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RAX *= RCX;
            RCX = imageBase + 0x7357B970;
            RAX += RBX;
            RAX += RCX;
            RAX += R11;
            return RAX;
        }
        case 1: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = 0x1637869ACC1CA2CF;
            RAX *= RCX;
            RAX -= RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
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
            RCX >>= 0x18;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x30;
            RAX ^= RCX;
            RAX -= R11;
            RCX = 0x4B7B3DFA17AEAF3A;
            RAX ^= RCX;
            RAX -= RBX;
            return RAX;
        }
        case 2: {
            R11 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            RDX = RBX;
            RDX = ~RDX;
            RCX = imageBase + 0x1A0B;
            RAX += RCX;
            RAX += RDX;
            RCX = RAX;
            RCX >>= 0x19;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x32;
            RAX ^= RCX;
            RCX = 0x243A49CEA3A34B9;
            RAX += RCX;
            RAX += R11;
            RCX = 0x1743A8056A5B9231;
            RAX *= RCX;
            RAX -= RBX;
            RCX = 0x3F4559AB397ACA5;
            RAX -= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            return RAX;
        }
        case 3: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RAX ^= R11;
            RAX -= RBX;
            RCX = RAX;
            RCX >>= 0x1E;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3C;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RAX *= RCX;
            RCX = imageBase + 0x2CE3;
            RAX += RBX;
            RAX += RCX;
            RCX = 0xA1D42548802279BD;
            RAX *= RCX;
            RCX = 0xEEFE4C944054D05D;
            RAX *= RCX;
            RCX = 0x393CAE01982658D;
            RAX -= RCX;
            return RAX;
        }
        case 4: {
            R11 = imageBase;
            R15 = imageBase + 0x1F59FD4E;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RAX *= RCX;
            RCX = 0xBD9C15574670779F;
            RAX *= RCX;
            RCX = imageBase + 0x5334C159;
            RCX -= RBX;
            RAX ^= RCX;
            RAX += RBX;
            RCX = RBX + 1;
            RCX *= R15;
            RAX += RCX;
            RCX = R11 + 0x0AB8;
            RCX += RBX;
            RAX ^= RCX;
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
            return RAX;
        }
        case 5: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R11 = imageBase;
            RDX = imageBase + 0x7499FB1C;
            RCX = 0x57DF5BD4F4BD798E;
            RAX -= RCX;
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
            RAX ^= R11;
            RCX = RDX;
            RCX = ~RCX;
            RCX ^= RBX;
            RAX -= RCX;
            RCX = 0x55115CF1E45B8B9D;
            RAX *= RCX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = imageBase + 0xDABC;
            RCX = ~RCX;
            RCX ^= RBX;
            RCX += RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x11;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x22;
            RAX ^= RCX;
            return RAX;
        }
        case 6: {
            R11 = readMemory<uint64_t>(imageBase + 0x689711B);
            RAX ^= RBX;
            RCX = RAX;
            RCX >>= 0x23;
            RAX ^= RCX;
            RAX ^= RBX;
            RDX = RBX;
            R8 = 0x0;
            R8 = _rotl64(R8, 0x10);
            RCX = imageBase + 0x240A;
            RDX *= RCX;
            R8 ^= R11;
            RCX = 0x505C98AB4E00B363;
            RCX *= RAX;
            R8 = _byteswap_uint64(R8);
            RCX -= RDX;
            RAX = readMemory<uint64_t>(R8 + 0x9);
            RAX *= RCX;
            RCX = 0xB669F2338F20107D;
            RAX *= RCX;
            RCX = 0xFFC18CC440709575;
            RAX *= RCX;
            return RAX;
        }
        case 7: {
            R11 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            RDX = RBX;
            RCX = imageBase + 0xF337;
            RDX *= RCX;
            RCX = RAX;
            RAX = 0x9738FFA2B633A137;
            RAX *= RCX;
            RAX += RDX;
            RDX = imageBase + 0x2FA7;
            RCX = RAX;
            RCX >>= 0x10;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x20;
            RAX ^= RCX;
            RCX = 0x84204EAFA3764204;
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
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = RBX;
            RCX = ~RCX;
            RCX -= R11;
            RCX += 0xFFFFFFFFC57771B2;
            RAX += RCX;
            RCX = RDX;
            RCX = ~RCX;
            RCX ^= RBX;
            RAX += RCX;
            return RAX;
        }
        case 8: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R15 = imageBase + 0x4B441AAE;
            RDX = RBX;
            RDX = ~RDX;
            RCX = imageBase + 0x4AC9E59D;
            RDX *= RCX;
            RCX = imageBase + 0xEC80;
            RDX += RBX;
            RAX += RCX;
            RAX += RDX;
            RCX = RBX;
            RCX *= R15;
            RAX += RCX;
            RDX = 0x0;
            RCX = RBX;
            RDX = _rotl64(RDX, 0x10);
            RCX = ~RCX;
            RCX ^= RAX;
            RDX ^= R10;
            RAX = imageBase + 0x7BFD1FA9;
            RCX ^= RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = 0xA8381BBBE1647E45;
            RAX *= RCX;
            RAX ^= RBX;
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
        case 9: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RAX *= RCX;
            RAX += RBX;
            RCX = R11 + 0x0AA50;
            RCX += RBX;
            RAX ^= RCX;
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
            RCX = 0x97A4AED046CFB2B1;
            RAX *= RCX;
            RCX = 0x8BECFFF65EE2C4F;
            RAX *= RCX;
            return RAX;
        }
        case 10: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = RAX;
            RCX >>= 0x1F;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3E;
            RAX ^= RCX;
            RAX -= RBX;
            RCX = 0x7E3A4A9603D9ACAF;
            RAX *= RCX;
            RAX += R11;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = 0x1603B2BB0B866539;
            RAX *= RCX;
            RCX = 0x361918C4648F0F5A;
            RAX += RCX;
            RCX = RAX;
            RCX >>= 0x1F;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3E;
            RAX ^= RCX;
            return RAX;
        }
        case 11: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R11 = imageBase;
            RCX = RAX;
            RCX >>= 0x11;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x22;
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
            RAX += R11;
            RCX = 0x6B8F155110A260C1;
            RAX *= RCX;
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
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = 0x24030F045C41CC6C;
            RAX += RCX;
            RCX = 0x29F8F12B1C9FE61C;
            RAX ^= RCX;
            return RAX;
        }
        case 12: {
            R15 = imageBase + 0x2C22;
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            RCX = RAX;
            RCX >>= 0xA;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = 0x9C3AFAF7DCF27427;
            RAX ^= RCX;
            RCX = RBX;
            RCX ^= R15;
            RAX += RCX;
            RCX = RAX;
            RCX >>= 0x19;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x32;
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
            RCX = 0x4102D8B2E93FF22B;
            RAX *= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = 0x2E517A6759AB60C1;
            RAX += RCX;
            return RAX;
        }
        case 13: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R11 = imageBase;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = RBX + RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = 0xD093588D1354DCFB;
            RAX *= RCX;
            RAX += R11;
            RCX = 0x23454F3ECF5210B1;
            RAX *= RCX;
            RAX -= R11;
            RCX = RAX;
            RCX >>= 0xE;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1C;
            RAX ^= RCX;
            RDX = RAX;
            RDX >>= 0x38;
            RAX ^= RDX;
            RCX = imageBase + 0x35AE457E;
            RCX = ~RCX;
            RCX ^= RBX;
            RAX -= RCX;
            return RAX;
        }
        case 14: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R11 = imageBase;
            RAX ^= R11;
            RCX = 0xE2D21CED0689D7F5;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x1F;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3E;
            RAX ^= RCX;
            RAX ^= R11;
            RAX -= RBX;
            RCX = 0xE04530525936FC81;
            RCX += RAX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RAX ^= RBX;
            return RAX;
        }
        case 15: {
            R10 = readMemory<uint64_t>(imageBase + 0x689711B);
            R11 = imageBase;
            RAX += RBX;
            RDX = 0x0;
            RCX = R11 + 0x891C;
            RCX += RBX;
            RDX = _rotl64(RDX, 0x10);
            RCX ^= RAX;
            RDX ^= R10;
            RAX = 0x6164D0B7E22A7180;
            RCX -= RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = 0x11589C83168D72B3;
            RAX *= RCX;
            RCX = 0x1F8E34A5D9298E17;
            RAX ^= RCX;
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
            RCX = RAX;
            RCX >>= 0x24;
            RAX ^= RCX;
            return RAX;
        }
        }
    }

    extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        R8 = readMemory<uint64_t>(imageBase + 0x15CBCC98);
        if (R8 == 0) {
            return 0;
        }
        RBX = peb; // mov rbx,gs:[rax]
        RBX = ~RBX;
        // test r8,r8
        // je 00007FF618785259h
        RAX = RBX;
        RAX <<= 0x1C;
        RAX = _byteswap_uint64(RAX);
        RAX &= 0xF;
        // cmp rax,0Eh
        // ja 00007FF618784D8Ch
        switch (RAX) {
        case 0: {
            R9 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0xA1A43FEE84EDB631;
            R8 *= RAX;
            RAX = imageBase + 0x6330B23A;
            RAX -= RBX;
            R8 += RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            R8 *= RAX;
            RAX = imageBase;
            R8 -= RAX;
            R8 ^= RBX;
            RAX = 0x9BBF4C8C90D57339;
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0x1F;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3E;
            R8 ^= RAX;
            RAX = 0xE2F3F76B380C10ED;
            R8 *= RAX;
            return R8;
        }
        case 1: {
            uint64_t RSP_0x78 = imageBase;
            // pushfq
            // push rcx
            // pop rcx
            // pop rcx
            // popfq
            RAX = imageBase + 0x6D66;
            RSP_0x78 = RAX; // mov [rsp+78h],rax
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x91EFE3E3DA8EB991;
            R8 *= RAX;
            R8 -= RBX;
            R8 -= RBX;
            RAX = 0x93FA3C880DC3D41F;
            R8 *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            R8 *= RAX;
            RAX = RBX;
            RAX ^= RSP_0x78; // xor rax,[rsp+78h]
            R8 ^= RBX;
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
            return R8;
        }
        case 2: {
            uint64_t RBP_NEG_0x40 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            R8 += RBX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0xF7F6BE8CDA66687;
            R8 ^= RAX;
            RAX = RBX;
            RAX = ~RAX;
            RAX -= RBP_NEG_0x40; // sub rax,[rbp-40h]
            RAX -= 0x2B2487DB;
            R8 ^= RAX;
            RAX = 0xB51552E6C8D09271;
            R8 *= RAX;
            R8 -= RBX;
            RAX = R8;
            RAX >>= 0xA;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x14;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x28;
            R8 ^= RAX;
            return R8;
        }
        case 3: {
            uint64_t RBP_NEG_0x78 = imageBase;
            RCX = imageBase + 0x3428;
            RBP_NEG_0x78 = RCX; // mov [rbp-78h],rcx
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = R8;
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            R8 = 0x703EBC784689EDDB;
            RAX ^= R8;
            R8 = readMemory<uint64_t>(RCX + 0xB);
            R8 *= RAX;
            RAX = 0x615CC716834829BB;
            R8 *= RAX;
            RCX = RBX;
            RCX = ~RCX;
            RAX = imageBase + 0x7E1D;
            RAX = ~RAX;
            RCX *= RAX;
            RAX = RBX + 1;
            RAX *= RBP_NEG_0x78; // imul rax,[rbp-78h]
            R8 += RAX;
            R8 += RCX;
            RAX = R8;
            RAX >>= 0x1F;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3E;
            R8 ^= RAX;
            RAX = imageBase;
            R8 += RAX;
            RAX = 0xF09040005C700D97;
            R8 *= RAX;
            return R8;
        }
        case 4: {
            uint64_t RSP_0x78 = imageBase;
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            // popfq
            RAX = imageBase + 0x3ECE65EC;
            RSP_0x78 = RAX; // mov [rsp+78h],rax
            R11 = imageBase + 0x7F0B5360;
            R9 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = R11;
            RAX = ~RAX;
            RAX++;
            RAX += RBX;
            R8 ^= RAX;
            RAX = RBX;
            RAX *= RSP_0x78; // imul rax,[rsp+78h]
            R8 ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            RAX = 0xA3451EFBBD533D9F;
            R8 *= RAX;
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
            RAX >>= 0x1F;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3E;
            R8 ^= RAX;
            RAX = 0xAF392642F3702325;
            R8 ^= RAX;
            return R8;
        }
        case 5: {
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x1DF706826A69DC07;
            R8 ^= RAX;
            RAX = imageBase;
            R8 += RAX;
            RAX = 0x2E2CDFE6AF62B35B;
            R8 *= RAX;
            R8 ^= RBX;
            RAX = R8;
            RAX >>= 0x28;
            RAX ^= R8;
            R8 = imageBase;
            RAX -= R8;
            R8 = RBX - 0x4111E235;
            R8 += RAX;
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
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            return R8;
        }
        case 6: {
            R9 = readMemory<uint64_t>(imageBase + 0x689721F);
            R8 ^= RBX;
            RAX = imageBase + 0x7BC1AA57;
            R8 ^= RAX;
            RAX = 0xC1FD15C9AACB35B3;
            R8 *= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0x8192B335F019E9FB;
            R8 *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            RAX = R8;
            RAX >>= 0x24;
            R8 ^= RAX;
            RAX = 0x2C05F4A90AC9B491;
            R8 *= RAX;
            R8 ^= RBX;
            return R8;
        }
        case 7: {
            // push rbx
            // pushfq
            // pop rbx
            // popfq
            // pop rbx
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RCX = imageBase + 0x6D8B;
            RCX = ~RCX;
            RAX = imageBase + 0x51AE0384;
            RAX = ~RAX;
            RCX += RBX;
            RAX ^= RBX;
            R8 ^= RCX;
            R8 -= RAX;
            RAX = imageBase;
            R8 -= RAX;
            R8 += 0xFFFFFFFF9E322DD7;
            R8 += RBX;
            RAX = 0xA1B6619E2F4DEB61;
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0xC;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x18;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x30;
            RAX ^= R8;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0xB);
            R8 *= RAX;
            RAX = 0xB6971AA79625277B;
            R8 *= RAX;
            RAX = 0xBAB392DBD08066AA;
            R8 ^= RAX;
            return R8;
        }
        case 8: {
            uint64_t RBP_NEG_0x40 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = imageBase + 0xD0F0;
            RBP_NEG_0x40 = RAX; // mov [rbp-40h],rax
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RAX = 0x8B138D029A9A9F65;
            RAX ^= R8;
            R8 = imageBase;
            RAX += R8;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0xB);
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0x15;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x2A;
            R8 ^= RAX;
            RAX = RBX;
            RAX *= RBP_NEG_0x40; // imul rax,[rbp-40h]
            R8 += RAX;
            RAX = 0x96BD03AC5042E305;
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0xC;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x18;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x30;
            R8 ^= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            return R8;
        }
        case 9: {
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = R8;
            RAX >>= 0x28;
            R8 ^= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = imageBase + 0x9895;
            RAX = ~RAX;
            RAX *= RBX;
            R8 ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            RAX = imageBase + 0x11BEFA15;
            RAX = ~RAX;
            RAX += RBX;
            R8 ^= RAX;
            RAX = 0x1AA06C3D06DB6919;
            R8 += RAX;
            RAX = R8;
            RAX >>= 0x1F;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3E;
            R8 ^= RAX;
            RAX = 0xD5880C601EF17849;
            R8 *= RAX;
            return R8;
        }
        case 10: {
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            RAX = R8;
            RAX >>= 0x24;
            R8 ^= RAX;
            RAX = imageBase;
            R8 += RAX;
            RAX = R8;
            RAX >>= 0x16;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x2C;
            R8 ^= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0x12CD767B439121F3;
            R8 ^= RAX;
            RAX = 0x45CB6DA49EFE83FB;
            R8 += RAX;
            RAX = 0xEE4DDDFAF76943D5;
            R8 *= RAX;
            return R8;
        }
        case 11: {
            uint64_t RBP_NEG_0x80 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x76ADBF35194102E1;
            RBP_NEG_0x80 = RAX; // mov [rbp-80h],rax
            RAX = imageBase + 0xF6E4;
            RAX = ~RAX;
            RAX += RBX;
            R8 += RAX;
            RAX = 0x4170DBFC76EF6392;
            R8 -= RAX;
            R8 ^= RBX;
            RAX = imageBase + 0xFE80;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x1B;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x36;
            R8 ^= RAX;
            R8 += RBX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            RAX *= RBP_NEG_0x80; // imul rax,[rbp-80h]
            R8 *= RAX;
            return R8;
        }
        case 12: {
            uint64_t RBP_NEG_0x78 = imageBase;
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            RAX = 0x88DC84CE86B57D7;
            RBP_NEG_0x78 = RAX; // mov [rbp-78h],rax
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            R8 += RBX;
            RAX = imageBase;
            RAX += 0x1644;
            RAX += RBX;
            R8 ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            RAX *= RBP_NEG_0x78; // imul rax,[rbp-78h]
            R8 *= RAX;
            RAX = 0xF1E802302A27EC4F;
            R8 *= RAX;
            R8 -= RBX;
            RAX = R8;
            RAX >>= 0x17;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x2E;
            R8 ^= RAX;
            return R8;
        }
        case 13: {
            uint64_t RSP_0x70 = imageBase;
            RDX = 0x84B73F80F0DBCCEF;
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            // popfq
            RAX = imageBase + 0x54724FBF;
            RSP_0x70 = RAX; // mov [rsp+70h],rax
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            R8 *= RAX;
            RAX = 0xD8995DAA21301973;
            R8 *= RAX;
            RAX = 0x7DD8CB17A9C7C1B8;
            R8 ^= RAX;
            RAX = imageBase;
            RAX += 0xBA5C;
            RAX += RBX;
            R8 += RAX;
            RAX = RBX;
            RAX = ~RAX;
            RAX += RSP_0x70; // add rax,[rsp+70h]
            R8 ^= RAX;
            R8 ^= RBX;
            RAX = imageBase + 0x62E88380;
            R8 ^= RAX;
            RAX = 0x77CC84A3E12C60D3;
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0x1E;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3C;
            R8 ^= RAX;
            return R8;
        }
        case 14: {
            R10 = readMemory<uint64_t>(imageBase + 0x689721F);
            RAX = RBX;
            RAX = ~RAX;
            RAX += 0xFFFFFFFFE08E6740;
            RAX += RBX;
            R8 += RAX;
            RAX = R8;
            RAX >>= 0x25;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3;
            R8 ^= RAX;
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
            RAX = 0x5AA8A80B55E17127;
            R8 -= RAX;
            RAX = 0x2A725435A657D1D0;
            R8 += RAX;
            RAX = 0xA9E4AC0C669E9691;
            R8 *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            return R8;
        }
        case 15: {
            // pop rbx
            // pop rbx
            R11 = readMemory<uint64_t>(imageBase + 0x689721F);
            RDX = imageBase + 0x8FA6;
            RAX = 0xF53D33388E9C7457;
            R8 *= RAX;
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
            R8 ^= RBX;
            R8 ^= RDX;
            RAX = 0x9EA3E70D9CADBBE1;
            R8 *= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0x34A2D09B6F1910B0;
            R8 -= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R11;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0xB);
            R8 += RBX;
            return R8;
        }
        }
    }

    extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RBX = index;
        RCX = RBX * 0x13C8;
        RAX = 0x67B4DA73B5283B59;
        R11 = imageBase;
        RAX = _umul128(RAX, RCX, &RDX);
        R10 = 0x86B9F8F6089E254D;
        RDX >>= 0xC;
        RAX = RDX * 0x277F;
        RCX -= RAX;
        RAX = 0xED68B13EC954000F;
        R8 = RCX * 0x277F;
        RAX = _umul128(RAX, R8, &RDX);
        RDX >>= 0xE;
        RAX = RDX * 0x4503;
        R8 -= RAX;
        RAX = 0x6A13CD153729043F;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R8;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0x9;
        RCX = RAX * 0x2D4;
        RAX = 0x47AE147AE147AE15;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R8;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0x4;
        RCX += RAX;
        RAX = RCX * 0x32;
        RCX = R8 * 0x34;
        RCX -= RAX;
        RAX = readMemory<uint16_t>(RCX + R11 + 0x68A7990);
        R8 = RAX * 0x13C8;
        RAX = R10;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R10;
        RDX >>= 0xC;
        RCX = RDX * 0x1E67;
        R8 -= RCX;
        R9 = R8 * 0x375C;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0xC;
        RAX = RDX * 0x1E67;
        R9 -= RAX;
        RAX = 0x14C75878C6B23E03;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = 0xAAAAAAAAAAAAAAAB;
        RDX >>= 0x7;
        RCX = RDX * 0x629;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0x2;
        RCX += RDX;
        RAX = RCX + RCX * 2;
        RCX = R9 * 0xE;
        RAX <<= 0x2;
        RCX -= RAX;
        R15 = readMemory<uint16_t>(RCX + R11 + 0x68B0700);
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