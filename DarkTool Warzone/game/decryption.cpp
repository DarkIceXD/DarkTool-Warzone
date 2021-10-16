#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
    extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

        RBX = readMemory<uint64_t>(imageBase + 0x18003B58);
        if (RBX == 0) {
            return 0;
        }
        uint64_t RSP_0x58 = imageBase;
        RSP_0x58 = 0xC; // mov byte ptr [rsp+58h],0Ch
        // movzx eax,byte ptr [rsp+58h]
        RAX = _rotr64(RAX, 0xAD);
        // movzx eax,al
        RDX = peb; // mov rdx,gs:[rax]
        RAX = RBX;
        RAX >>= 0x20;
        RBX ^= RAX;
        RAX = RBX;
        RAX >>= 0x28;
        RCX = 0x0;
        RAX ^= RDX;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= readMemory<uint64_t>(imageBase + 0x73A10F3);
        RAX ^= RBX;
        RDX = 0xC3A82EA730153563;
        RAX *= RDX;
        RCX = _byteswap_uint64(RCX);
        RDX = 0x7585B6D633F56AA9;
        RAX += RDX;
        RBX = readMemory<uint64_t>(RCX + 0x7);
        RBX *= RAX;
        return RBX;
    }

    extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RAX = readMemory<uint64_t>(clientInfo + 0x9FE08);
        RBX = peb; // mov rbx,gs:[rcx]
        // test rax,rax
        // je 00007FF663125E42h
        RCX = RBX;
        RCX <<= 0x1F;
        RCX = _byteswap_uint64(RCX);
        RCX &= 0xF;
        // cmp rcx,0Eh
        // ja 00007FF6631258BFh
        switch (RCX) {
        case 0: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RAX ^= R11;
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
            RDX = RAX;
            RDX >>= 0x20;
            RDX ^= RAX;
            RAX = imageBase + 0x25C1AEAB;
            RCX = RBX + 1;
            RAX *= RCX;
            RAX += RDX;
            RCX = 0xDB522B965B4BC7AF;
            RAX ^= RCX;
            RCX = 0x3430C6DC1F7FF1A;
            RAX ^= RCX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RDX = ~RDX;
            RCX = RAX;
            RCX >>= 0x23;
            RCX ^= RAX;
            RAX = readMemory<uint64_t>(RDX + 0xF);
            RAX *= RCX;
            RCX = 0x2C345461B3EE5423;
            RAX *= RCX;
            return RAX;
        }
        case 1: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RAX ^= R11;
            RCX = 0xE333EAB35837B803;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x12;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x24;
            RAX ^= RCX;
            RCX = RAX;
            RDX = 0x0;
            RAX = 0xBA3072D76B132722;
            RDX = _rotl64(RDX, 0x10);
            RCX ^= RAX;
            RDX ^= R10;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xF);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = 0xB7615EA41CBB7B04;
            RCX -= RBX;
            RAX += RCX;
            return RAX;
        }
        case 2: {
            R9 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RCX = 0x8F87F12EF0EAD8DD;
            RAX += RCX;
            RAX += R11;
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
            RAX += RBX;
            RCX = 0xFFB6DAF03FF792AF;
            RAX *= RCX;
            RCX = 0xF8304B2FE5036DE7;
            RAX ^= RCX;
            return RAX;
        }
        case 3: {
            R9 = readMemory<uint64_t>(imageBase + 0x73A1142);
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
            RCX >>= 0x1A;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x34;
            RAX ^= RCX;
            RCX = 0x61ED0265954DB8CD;
            RAX *= RCX;
            RCX = 0x3569AB2B4ECE32CB;
            RAX *= RCX;
            RCX = 0xA3F36DCFD2DFD3CB;
            RAX *= RCX;
            RAX -= RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            return RAX;
        }
        case 4: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R14 = imageBase + 0x25207982;
            RCX = RAX;
            RCX >>= 0x1A;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x34;
            RAX ^= RCX;
            RCX = 0x78C27013B60A2489;
            RAX *= RCX;
            RCX = 0x7B9ADA44E0063258;
            RAX += RCX;
            RCX = 0xF25571BEE96105B9;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RDX = RBX;
            RDX = ~RDX;
            RDX += R14;
            RDX ^= RAX;
            RAX = RBX * 0x1C0B;
            RAX += RDX;
            return RAX;
        }
        case 5: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RAX -= RBX;
            RCX = imageBase + 0x22DB95DB;
            RCX = ~RCX;
            RCX *= RBX;
            RAX += RCX;
            RAX ^= R11;
            RCX = 0x63BEE43ACC2AC8B1;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x9;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x12;
            RAX ^= RCX;
            RDX = RAX;
            RDX >>= 0x24;
            RDX ^= RAX;
            RAX = imageBase + 0x313A9755;
            RAX ^= RBX;
            RAX += RDX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RCX = 0x51746ACCE28E3EB1;
            RAX *= RCX;
            return RAX;
        }
        case 6: {
            uint64_t RSP_0x50 = imageBase;
            RCX = imageBase + 0x56D3506F;
            RSP_0x50 = RCX; // mov [rsp+50h],rcx
            R11 = imageBase;
            R15 = imageBase + 0x205DC2A8;
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0xD7BDB798FF999E31;
            RAX *= RCX;
            RCX = RBX;
            RCX *= RSP_0x50; // imul rcx,[rsp+50h]
            RAX += RCX;
            RCX = RBX + 1;
            RCX *= R15;
            RAX += RCX;
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
            RCX ^= RAX;
            RAX = RBX - 0x0FCB2;
            RCX -= R11;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RCX = RAX;
            RCX >>= 0x1D;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3A;
            RAX ^= RCX;
            RCX = 0x46586EC06F7F8991;
            RAX += RCX;
            return RAX;
        }
        case 7: {
            uint64_t RSP_0x50 = imageBase;
            RCX = 0x8E34EDEEA4AE91F5;
            RSP_0x50 = RCX; // mov [rsp+50h],rcx
            R15 = imageBase + 0x2E3A6F24;
            RDX = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= RDX;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xF);
            RCX *= RSP_0x50; // imul rcx,[rsp+50h]
            RAX *= RCX;
            RCX = RBX;
            RCX = ~RCX;
            RCX ^= R15;
            RAX -= RCX;
            RCX = RAX;
            RCX >>= 0x1C;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x38;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x7;
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
            RCX = 0x74703D461CCE880;
            RAX += RCX;
            return RAX;
        }
        case 8: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0xE57F16EE0604C7DD;
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
            RCX = 0x4799D34EFF6E151;
            RAX *= RCX;
            RCX = imageBase + 0x71455E19;
            RCX -= RBX;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xF);
            RAX *= RCX;
            RAX ^= RBX;
            RAX += RBX;
            RAX += R11;
            return RAX;
        }
        case 9: {
            R11 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0x2AF36CAB383EB42A;
            RCX -= R11;
            RAX += RCX;
            RCX = RBX;
            RCX = ~RCX;
            RCX -= R11;
            RCX += RAX;
            RAX = 0x374EA1A3B7E53749;
            RCX *= RAX;
            RAX = 0xDFA8AF566DFE784D;
            RAX += RCX;
            RAX += R11;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = 0x621538C1EB9B3437;
            RDX = ~RDX;
            RCX += RAX;
            RAX = readMemory<uint64_t>(RDX + 0xF);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x23;
            RAX ^= RCX;
            return RAX;
        }
        case 10: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RAX ^= R11;
            RAX -= R11;
            RAX += 0xFFFFFFFFFFFFE6E8;
            RAX += RBX;
            RCX = R11 + 0x62E0;
            RCX += RBX;
            RAX += RCX;
            RCX = 0xFCADF304F190ACB7;
            RAX *= RCX;
            RCX = 0xC1438856C2007645;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x27;
            RAX ^= RCX;
            RAX -= RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            return RAX;
        }
        case 11: {
            R11 = imageBase;
            RDX = imageBase + 0x3095AFF2;
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RAX -= R11;
            RAX += 0xFFFFFFFFAF32CBC6;
            RAX += RBX;
            RAX += RBX;
            RCX = RDX;
            RCX = ~RCX;
            RCX ^= RBX;
            RAX -= RCX;
            RCX = 0x7D999CDD0CDACE07;
            RAX *= RCX;
            RCX = 0x3C5569FD8BF085CD;
            RAX ^= RCX;
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
            RCX = 0x753B60EED8DD163B;
            RAX *= RCX;
            return RAX;
        }
        case 12: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R14 = imageBase + 0x16F2E291;
            R15 = imageBase + 0x45C8;
            RCX = RBX;
            RCX ^= R14;
            RAX -= RCX;
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
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xF);
            RAX *= RCX;
            RAX -= RBX;
            RAX += R15;
            RCX = 0x59789FCB171CD4A1;
            RAX -= RCX;
            RCX = RAX;
            RCX >>= 0x1F;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3E;
            RAX ^= RCX;
            RCX = 0x5E5CE79F43C3733F;
            RAX *= RCX;
            RAX ^= RBX;
            return RAX;
        }
        case 13: {
            R11 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0xFFFFFFFFB96F53C4;
            RCX -= RBX;
            RCX -= R11;
            RAX += RCX;
            RCX = RAX;
            RCX >>= 0x12;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x24;
            RAX ^= RCX;
            RCX = 0x902D46A3F82498B3;
            RAX *= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xF);
            RAX *= RCX;
            RCX = 0x8FA0F90EAFC8C6B6;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            RAX ^= R11;
            RCX = 0x149C6A33BC5EE03B;
            RAX += RCX;
            return RAX;
        }
        case 14: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            R11 = imageBase;
            RCX = RAX;
            RDX = 0x0;
            RCX -= R11;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xF);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x20;
            RAX ^= RCX;
            RCX = 0x4F2FBF191C05CEE8;
            RAX ^= RCX;
            RCX = 0x2A91DEB3CEF05FD5;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1E;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3C;
            RAX ^= RCX;
            RCX = 0x20C451C3DF92AA73;
            RAX *= RCX;
            RCX = imageBase + 0x7858A484;
            RCX = ~RCX;
            RCX += RAX;
            RAX = RBX + 1;
            RAX += RCX;
            return RAX;
        }
        case 15: {
            R11 = imageBase;
            RDX = imageBase + 0x7A5E6462;
            R10 = readMemory<uint64_t>(imageBase + 0x73A1142);
            RCX = 0x5C1AC48A90CC6077;
            RAX += RCX;
            RAX -= R11;
            RAX += 0xFFFFFFFF8933EAE8;
            RAX += RBX;
            RCX = 0x1228EB7CAFA8F8C3;
            RAX *= RCX;
            RCX = 0x7F16C3740C89C7AA;
            RAX += RCX;
            RAX ^= RBX;
            RAX ^= RDX;
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
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xF);
            RCX = RAX;
            RCX >>= 0x16;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2C;
            RAX ^= RCX;
            return RAX;
        }
        }
    }

    extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        R8 = readMemory<uint64_t>(imageBase + 0x15DC5A28);
        if (R8 == 0) {
            return 0;
        }
        RBX = peb; // mov rbx,gs:[rax]
        RBX = ~RBX;
        // test r8,r8
        // je 00007FF66328BFB6h
        RAX = RBX;
        RAX = _rotr64(RAX, 0x1A);
        RAX &= 0xF;
        // cmp rax,0Eh
        // ja 00007FF66328BAAEh
        switch (RAX) {
        case 0: {
            R11 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RDX = imageBase + 0x3BC2901E;
            R8 -= RBX;
            RAX = 0x61553433E19B551F;
            R8 *= RAX;
            RAX = R8;
            RAX >>= 0x26;
            RAX ^= R8;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R11;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RCX = RBX + 1;
            RAX = R8;
            RCX *= RDX;
            R8 = 0xA687B1F47C7DA601;
            R8 ^= RAX;
            R8 += RCX;
            RCX = RBX;
            RCX = ~RCX;
            RAX = imageBase + 0x6628;
            RAX = ~RAX;
            R8 += RAX;
            R8 += RCX;
            RAX = R8;
            RAX >>= 0x26;
            R8 ^= RAX;
            return R8;
        }
        case 1: {
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = 0x6099CEDB002A083B;
            R8 += RAX;
            R8 ^= RBX;
            RAX = imageBase + 0x758EFD47;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x1C;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x38;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x19;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x32;
            RAX ^= R8;
            RCX = 0x0;
            RAX += RBX;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            R8 = 0x8BE7BD85D52F1747;
            RAX *= R8;
            RCX = _byteswap_uint64(RCX);
            R8 = 0x2A337D5C12B6D3B5;
            RAX -= R8;
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            return R8;
        }
        case 2: {
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            RCX = imageBase + 0xFBA0;
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = 0x81ECF51CBDF8783B;
            R8 *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0x13);
            RAX = 0xD69D866641C327BB;
            R8 *= RAX;
            RAX = RBX;
            RAX ^= RCX;
            R8 -= RAX;
            RAX = R8;
            RAX >>= 0x15;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x2A;
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
            RAX >>= 0x28;
            R8 ^= RAX;
            RAX = 0x40052EAD9D58C611;
            R8 *= RAX;
            return R8;
        }
        case 3: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            R8 -= RBX;
            RAX = R8;
            RAX >>= 0x1A;
            R8 ^= RAX;
            RCX = R8;
            RCX >>= 0x34;
            RCX ^= R8;
            R8 = imageBase + 0xBB60;
            R8 *= RBX;
            R8 += RCX;
            R8 ^= RBX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0x13);
            RAX = 0xB4B0FF409800A8D3;
            R8 *= RAX;
            RAX = 0x3A7EB1C57B8CE23F;
            R8 += RAX;
            return R8;
        }
        case 4: {
            // pushfq
            // push rbx
            // pop rbx
            // pop rbx
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RCX = imageBase + 0xA324;
            RAX = RBX;
            RAX = ~RAX;
            RAX *= RCX;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0xA;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x14;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x28;
            RAX ^= R8;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RAX = 0x62D83838E6786A2D;
            R8 *= RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0xF66387750387D537;
            R8 *= RAX;
            R8 -= RBX;
            RAX = 0xF800EEF50065BDE1;
            R8 *= RAX;
            return R8;
        }
        case 5: {
            uint64_t RBP_NEG_0x20 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = RBX;
            RAX -= RBP_NEG_0x20; // sub rax,[rbp-20h]
            RCX ^= R10;
            RAX += R8;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RAX = 0x35A5A7375E8CB65E;
            R8 -= RAX;
            RAX = R8;
            RAX >>= 0x1F;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3E;
            R8 ^= RAX;
            RAX = imageBase + 0x63DB896D;
            RAX = ~RAX;
            R8 -= RBX;
            R8 += RAX;
            RAX = 0x9ED78104E498528B;
            R8 *= RAX;
            RAX = 0x39E3D3AF8545F10E;
            R8 += RAX;
            return R8;
        }
        case 6: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = R8;
            RCX = 0x0;
            RAX >>= 0x10;
            R8 ^= RAX;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RAX = R8;
            RAX >>= 0x20;
            RAX ^= R8;
            RCX = _byteswap_uint64(RCX);
            RAX -= RBX;
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            R8 += RBX;
            RAX = imageBase;
            RAX += 0x5768;
            RAX += RBX;
            R8 += RAX;
            RAX = 0xBA435D04CBDDDF02;
            R8 ^= RAX;
            RAX = 0xAAD63848BA6D8E21;
            R8 *= RAX;
            RAX = 0x4FB525C7AE28EDBE;
            R8 -= RAX;
            return R8;
        }
        case 7: {
            uint64_t RBP_NEG_0x48 = imageBase;
            uint64_t RSP_0x78 = imageBase;
            RDX = 0x9978E9758AF31E99;
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            // popfq
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = imageBase + 0xEB4D;
            RBP_NEG_0x48 = RAX; // mov [rbp-48h],rax
            RAX = imageBase + 0x58A6D9DC;
            RSP_0x78 = RAX; // mov [rsp+78h],rax
            RAX = RBX;
            RAX *= RBP_NEG_0x48; // imul rax,[rbp-48h]
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x26;
            R8 ^= RAX;
            RAX = RBX;
            RCX = 0x3ADCE34A853CD7D4;
            RAX *= RSP_0x78; // imul rax,[rsp+78h]
            RAX += RCX;
            R8 += RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = RBX;
            RAX ^= R8;
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RAX = 0x25D2FC3F8B7382D9;
            R8 += RAX;
            RAX = 0x28DED016A8BAC9F7;
            R8 *= RAX;
            return R8;
        }
        case 8: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = R8;
            RAX >>= 0xC;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x18;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x30;
            R8 ^= RAX;
            RAX = imageBase + 0x515BEDE6;
            RAX -= RBX;
            R8 += RAX;
            RAX = R8;
            RAX >>= 0xB;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x16;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x2C;
            R8 ^= RAX;
            RAX = 0x642D1B5DF5B223E6;
            R8 += RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = R8;
            RCX ^= R10;
            R8 = 0x997EF470472F0CA4;
            RAX ^= R8;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RAX = imageBase + 0x9BA9;
            R8 += RBX;
            R8 += RAX;
            RAX = 0x28C19C37DF3A9A5F;
            R8 *= RAX;
            return R8;
        }
        case 9: {
            R9 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0x13);
            RAX = 0x97C6E4BCB98FC57C;
            R8 ^= RAX;
            RAX = imageBase + 0x5958;
            RAX = ~RAX;
            RAX *= RBX;
            R8 += RAX;
            RAX = imageBase;
            R8 ^= RAX;
            RAX = 0x20C032D918E9569F;
            R8 ^= RAX;
            RAX = 0xB33DF548E2DCC13;
            R8 *= RAX;
            RAX = imageBase;
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
            return R8;
        }
        case 10: {
            uint64_t RBP_NEG_0x48 = imageBase;
            RAX = imageBase + 0xDFE5;
            RBP_NEG_0x48 = RAX; // mov [rbp-48h],rax
            R9 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = imageBase;
            R8 += RAX;
            RAX = R8;
            RAX >>= 0xD;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x1A;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x34;
            R8 ^= RAX;
            RAX = 0x2E6985DD4F2E9E95;
            R8 *= RAX;
            RAX = 0x6E3CA0BC66A1C823;
            R8 ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = _byteswap_uint64(RAX);
            R8 *= readMemory<uint64_t>(RAX + 0x13);
            RAX = RBX;
            RAX ^= RBP_NEG_0x48; // xor rax,[rbp-48h]
            R8 += RAX;
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
            RAX >>= 0x1A;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x34;
            R8 ^= RAX;
            return R8;
        }
        case 11: {
            R11 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = imageBase;
            RAX += 0xFBD9;
            RAX += RBX;
            R8 ^= RAX;
            R8 ^= RBX;
            RAX = 0x75CEE2F00F3A51EB;
            R8 *= RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = R8;
            RCX ^= R11;
            RAX >>= 0x28;
            RAX ^= R8;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            RAX = imageBase;
            RAX += 0x65384FF1;
            RAX += RBX;
            R8 ^= RAX;
            RAX = 0xAA1B46D75995200F;
            R8 *= RAX;
            RAX = 0x18A5AA8A7C9E9081;
            R8 *= RAX;
            return R8;
        }
        case 12: {
            // push rbx
            // pushfq
            // pop rbx
            // popfq
            // pop rbx
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = imageBase + 0x7E00;
            RCX = RBX;
            RCX *= RAX;
            RAX = R8;
            RAX >>= 0x24;
            RCX ^= RAX;
            R8 ^= RCX;
            RAX = imageBase;
            R8 ^= RAX;
            RCX = imageBase + 0xF30F;
            RCX = ~RCX;
            RCX++;
            RCX += RBX;
            R8 ^= RCX;
            RAX = 0x3EDA427466FD981D;
            R8 *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0x13);
            R8 *= RAX;
            RAX = 0x9BF2FF217558E40F;
            R8 ^= RAX;
            RAX = 0x5F0F89D7CC9D3D87;
            R8 += RAX;
            return R8;
        }
        case 13: {
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            R8 -= RBX;
            R8 ^= RBX;
            R8 -= RBX;
            RAX = 0xD00603C660809D;
            R8 *= RAX;
            RAX = 0xFD4C18450B989581;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0xA;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x14;
            R8 ^= RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RAX = R8;
            RCX = _byteswap_uint64(RCX);
            RAX >>= 0x28;
            RAX ^= R8;
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            return R8;
        }
        case 14: {
            R11 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = R8;
            RAX >>= 0xF;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x1E;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x3C;
            R8 ^= RAX;
            RCX = RBX + R8;
            R8 = 0xB1B72B6AD3E9E45A;
            RAX = 0x58DB95B569F4F22D;
            RCX *= RAX;
            RAX = imageBase + 0x4B5C;
            RAX *= R8;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RCX += RAX;
            RDX ^= R11;
            RAX = 0x1D79F512CB5E7371;
            RDX = _byteswap_uint64(RDX);
            RCX ^= RAX;
            R8 = readMemory<uint64_t>(RDX + 0x13);
            R8 *= RCX;
            RAX = 0x40CB7287482B0D5F;
            R8 -= RAX;
            RAX = R8;
            RAX >>= 0x10;
            R8 ^= RAX;
            RAX = R8;
            RAX >>= 0x20;
            R8 ^= RAX;
            return R8;
        }
        case 15: {
            uint64_t RBP_NEG_0x48 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x73A11FA);
            RAX = imageBase + 0x49AAD041;
            RBP_NEG_0x48 = RAX; // mov [rbp-48h],rax
            R13 = imageBase + 0x4F03549A;
            RAX = RBX;
            RAX ^= R13;
            R8 -= RAX;
            R8 -= RBX;
            RAX = 0x5BA6DBA1F387ECE1;
            R8 *= RAX;
            RAX = 0x71B0B56619F657D5;
            R8 *= RAX;
            RAX = 0x2C08D526B0A4A38B;
            R8 ^= RAX;
            RAX = RBX;
            RAX *= RBP_NEG_0x48; // imul rax,[rbp-48h]
            R8 -= RAX;
            RAX = R8;
            RAX >>= 0x12;
            R8 ^= RAX;
            RCX = 0x0;
            RAX = R8;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RAX >>= 0x24;
            RAX ^= R8;
            RCX = _byteswap_uint64(RCX);
            R8 = readMemory<uint64_t>(RCX + 0x13);
            R8 *= RAX;
            return R8;
        }
        }
    }

    extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RBX = index;
        RCX = RBX * 0x13C8;
        RAX = 0x38AE5B395E3D4CAF;
        R11 = imageBase;
        RAX = _umul128(RAX, RCX, &RDX);
        RAX = RCX;
        R10 = 0x84B6DEFBC166BE53;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0xC;
        RAX = RAX * 0x1A33;
        RCX -= RAX;
        RAX = 0xACA5D1C2D702414B;
        R8 = RCX * 0x1A33;
        RAX = _umul128(RAX, R8, &RDX);
        RDX >>= 0xD;
        RAX = RDX * 0x2F73;
        R8 -= RAX;
        RAX = 0xBC0D38EE00BC0D39;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = 0xD79435E50D79435F;
        RDX >>= 0x9;
        RCX = RDX * 0x2B9;
        RAX = _umul128(RAX, R8, &RDX);
        RDX >>= 0x4;
        RCX += RDX;
        RAX = RCX * 0x26;
        RCX = R8 + R8 * 4;
        RCX <<= 0x3;
        RCX -= RAX;
        RAX = readMemory<uint16_t>(RCX + R11 + 0x73AFF80);
        R8 = RAX * 0x13C8;
        RAX = R10;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R10;
        RDX >>= 0xC;
        RCX = RDX * 0x1EDD;
        R8 -= RCX;
        R9 = R8 * 0x26C2;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0xC;
        RAX = RDX * 0x1EDD;
        R9 -= RAX;
        RAX = 0xCCCCCCCCCCCCCCCD;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = 0x6279F0FF6C491681;
        RDX >>= 0x3;
        RCX = RDX + RDX * 4;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0x9;
        RAX = RDX + RCX * 2;
        RCX = RAX * 0xA66;
        RAX = R9 * 0xA68;
        RAX -= RCX;
        R15 = readMemory<uint16_t>(RAX + R11 + 0x73B6700);
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