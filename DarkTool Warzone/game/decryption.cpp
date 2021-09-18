#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
    extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

        RBX = readMemory<uint64_t>(imageBase + 0x179E7B58);
        if (RBX == 0) {
            return 0;
        }
        uint64_t RSP_0x60 = imageBase;
        RSP_0x60 = 0x30; // mov byte ptr [rsp+60h],30h
        // movzx eax,byte ptr [rsp+60h]
        RAX = _rotl64(RAX, 0x99);
        // movzx eax,al
        R8 = peb; // mov r8,gs:[rax]
        RAX = RBX;
        RAX >>= 0x25;
        RCX = 0x0;
        RAX ^= RBX;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= readMemory<uint64_t>(imageBase + 0x743510F);
        RCX = ~RCX;
        RDX = readMemory<uint64_t>(RCX + 0xD);
        RDX *= RAX;
        RAX = imageBase + 0x48213716;
        RAX = ~RAX;
        RAX *= R8;
        RDX += RAX;
        RAX = RDX;
        RAX >>= 0x4;
        RDX ^= RAX;
        RAX = RDX;
        RAX >>= 0x8;
        RDX ^= RAX;
        RAX = RDX;
        RAX >>= 0x10;
        RDX ^= RAX;
        RAX = 0xC5A784A827A2D14B;
        RBX = RDX;
        RBX >>= 0x20;
        RBX ^= RDX;
        RBX ^= RAX;
        RAX = 0xD5D6616344B44B01;
        RBX *= RAX;
        return RBX;
    }

    extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RAX = readMemory<uint64_t>(clientInfo + 0x9ED78);
        RDI = peb; // mov rdi,gs:[rcx]
        RDI = ~RDI;
        // test rax,rax
        // je 00007FF6C53CBB6Bh
        RCX = RDI;
        RCX = _rotl64(RCX, 0x21);
        RCX &= 0xF;
        // cmp rcx,0Eh
        // ja 00007FF6C53CB72Bh
        switch (RCX) {
        case 0: {
            R15 = imageBase + 0xDFB3;
            RBX = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RCX = RDI;
            RCX *= R15;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = 0x277829E1ED60D087;
            RAX *= RCX;
            RAX -= RDI;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RCX = RAX;
            RDX ^= R10;
            RCX -= RBX;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RCX = 0x34E84446E2735013;
            RAX -= RCX;
            RAX += RBX;
            return RAX;
        }
        case 1: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RBX = imageBase;
            RAX += RDI;
            RCX = 0x77C72DC2F51246ED;
            RAX *= RCX;
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
            RCX = 0x37CC55FEF73F5D6C;
            RAX += RCX;
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
            RCX = 0x6A15FF653968A0E7;
            RAX ^= RCX;
            RAX -= RBX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = RAX - 0x7A9DFB7F;
            RDX = ~RDX;
            RCX += RDI;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            return RAX;
        }
        case 2: {
            RBX = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
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
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xB);
            RCX = RDI;
            RCX = ~RCX;
            RCX -= RBX;
            RCX += 0xFFFFFFFF855CFB0C;
            RAX += RCX;
            RAX ^= RDI;
            RCX = 0x667D4DD4C0F566A2;
            RAX -= RCX;
            RAX += RBX;
            RCX = 0xFFF68C8AD2A3FC45;
            RAX *= RCX;
            return RAX;
        }
        case 3: {
            RBX = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x7435152);
            RCX = RBX + 0x4C2D7B1A;
            RCX += RDI;
            RCX ^= RDI;
            RAX ^= RCX;
            R11 = 0x1C62BFAEA6023858;
            RCX = RDI;
            RCX = ~RCX;
            RCX -= RBX;
            RCX += R11;
            RAX += RCX;
            RCX = 0xF7608F5F4CBD0167;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x24;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xB);
            RCX = 0x7A09407BEB0E8D5F;
            RAX -= RCX;
            return RAX;
        }
        case 4: {
            R11 = readMemory<uint64_t>(imageBase + 0x7435152);
            R15 = imageBase + 0x8082;
            RDX = RDI;
            R8 = 0x0;
            RCX = 0xD80DD5766808D249;
            R8 = _rotl64(R8, 0x10);
            RCX ^= RAX;
            RDX *= R15;
            R8 ^= R11;
            R8 = ~R8;
            RCX -= RDX;
            RAX = readMemory<uint64_t>(R8 + 0xB);
            RAX *= RCX;
            RCX = 0xF5795C270C91F70B;
            RAX *= RCX;
            RCX = 0x666F679F6A945213;
            RAX -= RCX;
            RAX -= RDI;
            RCX = RAX;
            RCX >>= 0x18;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x30;
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
            return RAX;
        }
        case 5: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            R15 = imageBase + 0x170B635D;
            RCX = RAX;
            RCX >>= 0xF;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1E;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3C;
            RAX ^= RCX;
            RCX = 0xD6A9A27E11D7B4DD;
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
            RCX = RDI;
            RCX = ~RCX;
            RDX = 0x0;
            RCX *= R15;
            RDX = _rotl64(RDX, 0x10);
            RCX ^= RAX;
            RDX ^= R10;
            RAX = 0x5BFE87D0BC9F4297;
            RDX = ~RDX;
            RCX ^= RAX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RDX = imageBase + 0xF77F;
            RDX = ~RDX;
            RDX ^= RDI;
            RDX -= RDI;
            RCX = imageBase + 0x397BE373;
            RAX += RCX;
            RAX += RDX;
            return RAX;
        }
        case 6: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RDX = imageBase + 0x9761;
            RDX = ~RDX;
            RDX += RDI;
            RCX = imageBase + 0x1;
            RAX += RCX;
            RAX += RDX;
            RCX = 0x1D8AD81E00811427;
            RCX *= RAX;
            RDX = 0x0;
            RAX = 0x1F683777275965F8;
            RDX = _rotl64(RDX, 0x10);
            RCX -= RAX;
            RDX ^= R10;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RAX ^= RDI;
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            RCX = 0x74F76D96DC4C6A03;
            RAX -= RCX;
            return RAX;
        }
        case 7: {
            R15 = imageBase + 0x4609;
            RBX = imageBase + 0x6361;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RDX = imageBase + 0xE70F;
            RCX = R15;
            RCX -= RDI;
            RAX ^= RCX;
            RAX ^= RDI;
            RAX ^= RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xB);
            RCX = 0x3B68F870D2C93BD5;
            RAX *= RCX;
            RCX = RDI;
            RCX = ~RCX;
            RAX ^= RCX;
            RAX ^= RDX;
            RCX = 0xBFFD95E658B6279F;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            RAX ^= RDI;
            return RAX;
        }
        case 8: {
            R15 = imageBase + 0x96B0;
            RDX = imageBase + 0xC386;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RAX += RDI;
            RCX = imageBase + 0x5AF9C6B8;
            RAX += RCX;
            RCX = 0x1C0AC01ED9D90D52;
            RAX ^= RCX;
            RCX = RDI;
            RCX ^= RDX;
            RAX += RCX;
            RCX = R15;
            RCX = ~RCX;
            RDX = 0x0;
            RCX ^= RDI;
            RCX ^= RAX;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x20;
            RCX ^= RDI;
            RAX ^= RCX;
            RCX = 0xB9C498A1F4BD2271;
            RAX *= RCX;
            return RAX;
        }
        case 9: {
            R11 = readMemory<uint64_t>(imageBase + 0x7435152);
            RBX = imageBase;
            RAX += RBX;
            RCX = 0x1C17BBB58A151199;
            RAX ^= RCX;
            RCX = imageBase + 0x1919;
            RDX = RAX;
            RCX = ~RCX;
            RDX >>= 0x20;
            RDX ^= RAX;
            R8 = 0x0;
            RCX *= RDI;
            R8 = _rotl64(R8, 0x10);
            RAX = 0xF734865D02323EE5;
            RDX *= RAX;
            R8 ^= R11;
            RAX = 0x2107E12261DB458D;
            RAX += RDX;
            R8 = ~R8;
            RCX += RAX;
            RAX = readMemory<uint64_t>(R8 + 0xB);
            RAX *= RCX;
            RAX ^= RBX;
            return RAX;
        }
        case 10: {
            uint64_t RSP_0x48 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RBX = imageBase;
            RCX = 0x387C1FE4ED3B4863;
            RSP_0x48 = RCX; // mov [rsp+48h],rcx
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = RDI;
            RCX ^= RAX;
            RDX = ~RDX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RAX *= RSP_0x48; // imul rax,[rsp+48h]
            RCX = RBX + 0x7CE5;
            RCX += RDI;
            RAX ^= RCX;
            RCX = 0x9A138B96132F1187;
            RAX *= RCX;
            RCX = 0x7086E8AACB9F7C74;
            RAX -= RCX;
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
            RCX = RAX;
            RCX >>= 0x20;
            RAX ^= RCX;
            return RAX;
        }
        case 11: {
            uint64_t RSP_0x58 = imageBase;
            RCX = 0x48A357C332FDD3EF;
            RSP_0x58 = RCX; // mov [rsp+58h],rcx
            RBX = imageBase;
            R11 = imageBase + 0xE796;
            R9 = readMemory<uint64_t>(imageBase + 0x7435152);
            RCX = 0x1A36166635DC7C5A;
            RAX ^= RCX;
            RAX ^= RBX;
            RCX = RAX;
            RCX >>= 0x1E;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3C;
            RAX ^= RCX;
            RAX -= RDI;
            RCX = RDI;
            RCX *= R11;
            RAX += RCX;
            RCX = RBX + 0x4780BA53;
            RCX += RDI;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xB);
            RCX *= RSP_0x58; // imul rcx,[rsp+58h]
            RAX *= RCX;
            return RAX;
        }
        case 12: {
            RBX = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x7435152);
            RAX -= RBX;
            RAX += 0xFFFFFFFFDEDB6344;
            RAX += RDI;
            RCX = 0xC5D0EA7EAB558262;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xB);
            RAX *= RCX;
            RCX = 0xB9391395782B9FF4;
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
            RAX -= RDI;
            RCX = 0x900A6C3FD54DF2C7;
            RAX -= RBX;
            RAX *= RCX;
            RCX = 0x2CDCB8D304E72C29;
            RAX += RCX;
            RAX += RDI;
            return RAX;
        }
        case 13: {
            uint64_t RSP_0x50 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RCX = imageBase + 0x5B8E3B28;
            RSP_0x50 = RCX; // mov [rsp+50h],rcx
            RBX = imageBase;
            RAX += RBX;
            RCX = RAX;
            RCX >>= 0x1B;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x36;
            RAX ^= RCX;
            RAX -= RBX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = RDI;
            RCX = ~RCX;
            RDX = ~RDX;
            RCX ^= RSP_0x50; // xor rcx,[rsp+50h]
            RCX += RAX;
            RAX = readMemory<uint64_t>(RDX + 0xB);
            RAX *= RCX;
            RCX = 0x9D81587D24DEAFE3;
            RAX += RCX;
            RCX = 0xDA30BD40EFAC1FCA;
            RAX ^= RCX;
            RCX = 0x9CCF39856C3AD817;
            RAX *= RCX;
            return RAX;
        }
        case 14: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            R15 = imageBase + 0x3980;
            RDX = RDI;
            RDX = ~RDX;
            RCX = imageBase + 0x54298248;
            RAX += RCX;
            RAX += RDX;
            RCX = RAX;
            RCX >>= 0xB;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x16;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2C;
            RAX ^= RCX;
            RDX = RDI;
            RDX = ~RDX;
            RCX = R15;
            RCX = ~RCX;
            RDX *= RCX;
            RCX = RAX;
            RCX >>= 0x27;
            RAX ^= RCX;
            RAX += RDX;
            RCX = 0xB8D582BA369905D7;
            RAX *= RCX;
            RCX = 0x1250819ACC854701;
            RAX *= RCX;
            RCX = 0x7F5E55208C63F780;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RAX *= readMemory<uint64_t>(RCX + 0xB);
            return RAX;
        }
        case 15: {
            uint64_t RSP_0x58 = imageBase;
            RCX = 0xE736A6EEE4DC3473;
            RSP_0x58 = RCX; // mov [rsp+58h],rcx
            RBX = imageBase;
            R13 = 0x7DBDD8A43A8AE359;
            R10 = readMemory<uint64_t>(imageBase + 0x7435152);
            RCX = imageBase + 0x9CEF;
            RCX -= RDI;
            RAX += RCX;
            RCX = 0xFA77DD378B76D0E8;
            RAX ^= RCX;
            RAX *= R13;
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
            RAX += RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = ~RCX;
            RCX = readMemory<uint64_t>(RCX + 0xB);
            RCX *= RSP_0x58; // imul rcx,[rsp+58h]
            RAX *= RCX;
            return RAX;
        }
        }
    }

    extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RDX = readMemory<uint64_t>(imageBase + 0x15CD0C08);
        if (RDX == 0) {
            return 0;
        }
        R8 = peb; // mov r8,gs:[rax]
        // test rdx,rdx
        // je 00007FF6C56A1E9Fh
        RAX = R8;
        RAX = _rotl64(RAX, 0x2E);
        RAX &= 0xF;
        // cmp rax,0Eh
        // ja 00007FF6C56A1A47h
        switch (RAX) {
        case 0: {
            R15 = imageBase + 0xBCAC;
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = RDX;
            RDX = 0xFE2423D88B4F5199;
            RDX *= RAX;
            RDX += R8;
            RDX += R15;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0xB;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x16;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x2C;
            RDX ^= RAX;
            RDX += R8;
            RAX = 0x5B95F641EEB10C08;
            RDX ^= RAX;
            RAX = imageBase;
            RDX -= RAX;
            RAX = 0xA25AF61EC84A8CD3;
            RDX ^= RAX;
            return RDX;
        }
        case 1: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x9F5FE91CBE5F4A71;
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x3;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x6;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0xC;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x18;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x30;
            RDX ^= RAX;
            RAX = imageBase;
            RAX = RAX * 0xFE;
            RDX += RAX;
            RAX = imageBase;
            RDX += RAX;
            RAX = RDX;
            RAX >>= 0x1;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x2;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x4;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x8;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x10;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            RAX = imageBase + 0x7CA1DFE4;
            RAX = ~RAX;
            RAX += R8;
            RDX += RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            return RDX;
        }
        case 2: {
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= RBX;
            RAX = imageBase + 0x9C36;
            RAX += RDX;
            RAX += R8;
            RCX = _byteswap_uint64(RCX);
            RDX = readMemory<uint64_t>(RCX + 0xB);
            RDX *= RAX;
            RAX = 0xCFA0318D63B75B3;
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x21;
            RDX ^= RAX;
            RAX = 0x651C17D7237682F8;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            RDX -= R8;
            RAX = imageBase + 0x2212F0A0;
            RAX -= R8;
            RDX += RAX;
            return RDX;
        }
        case 3: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0xBA31F424A4BA6E9;
            RDX *= RAX;
            RAX = imageBase + 0x7AA841F1;
            RAX = ~RAX;
            RAX -= R8;
            RDX += RAX;
            RAX = RDX;
            RAX >>= 0x19;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x32;
            RDX ^= RAX;
            RAX = 0xEF4695006A88EF29;
            RDX *= RAX;
            RCX = imageBase + 0x6D8F;
            RCX = ~RCX;
            RAX = R8;
            RAX = ~RAX;
            RCX *= RAX;
            RAX = RDX;
            RDX = 0xFEFDFB4B9F864825;
            RDX *= RAX;
            RDX += RCX;
            RCX = 0x0;
            RAX = RDX;
            RCX = _rotl64(RCX, 0x10);
            RDX = imageBase;
            RAX ^= RDX;
            RCX ^= RBX;
            RCX = _byteswap_uint64(RCX);
            RDX = readMemory<uint64_t>(RCX + 0xB);
            RDX *= RAX;
            return RDX;
        }
        case 4: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            R12 = imageBase + 0xC439;
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x7095A843091D405;
            RDX *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= RBX;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0x1B;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x36;
            RDX ^= RAX;
            RAX = 0x5F1C9F052C9777DE;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x7;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0xE;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x1C;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x38;
            RDX ^= RAX;
            RAX = imageBase;
            RDX -= RAX;
            RAX = R12;
            RAX = ~RAX;
            RAX += R8;
            RDX ^= RAX;
            RAX = 0xB363162ED8370562;
            RDX ^= RAX;
            return RDX;
        }
        case 5: {
            uint64_t RSP_0x48 = imageBase;
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            RAX = 0x76DBDBAD9AB67A6D;
            RSP_0x48 = RAX; // mov [rsp+48h],rax
            R15 = imageBase + 0x79FB;
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RAX = readMemory<uint64_t>(RAX + 0xB);
            RAX *= RSP_0x48; // imul rax,[rsp+48h]
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x9;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x12;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x24;
            RDX ^= RAX;
            RAX = R8 + RDX;
            RDX = 0x6908DBD850006E3F;
            RAX += RDX;
            RDX = imageBase;
            RDX += RAX;
            RAX = 0xA88EDB400790BD21;
            RDX *= RAX;
            RDX ^= R8;
            RAX = R15;
            RAX ^= R8;
            RDX -= RAX;
            return RDX;
        }
        case 6: {
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0x13;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x26;
            RDX ^= RAX;
            RAX = 0xB555A0513AE06CFB;
            RDX *= RAX;
            RAX = 0xA1A2750C5114503E;
            RDX ^= RAX;
            RDX ^= R8;
            RDX += R8;
            RAX = imageBase + 0xACC0;
            RAX -= R8;
            RDX ^= RAX;
            RAX = 0x7BF17FB1A7DAE793;
            RDX ^= RAX;
            return RDX;
        }
        case 7: {
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            R15 = imageBase + 0x72D1842B;
            RAX = R8;
            RAX = ~RAX;
            RAX *= R15;
            RDX ^= RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = RDX;
            RCX ^= RBX;
            RCX = _byteswap_uint64(RCX);
            RAX ^= R8;
            RDX = readMemory<uint64_t>(RCX + 0xB);
            RDX *= RAX;
            RDX -= R8;
            RAX = RDX;
            RAX >>= 0x26;
            RDX ^= RAX;
            RAX = 0xEC0CF58EA5B2E43;
            RDX ^= RAX;
            RAX = 0x74A820D7670BC20D;
            RDX *= RAX;
            return RDX;
        }
        case 8: {
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            R15 = imageBase + 0x7BE7FF79;
            RAX = 0xEB29FDA69081974B;
            RDX *= RAX;
            RAX = 0x35BD24AF876C8C81;
            RDX ^= RAX;
            RAX = R15;
            RAX *= R8;
            RDX -= RAX;
            RDX -= R8;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= RBX;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0x18;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x30;
            RDX ^= RAX;
            RAX = 0x6E77D78EE4C71273;
            RDX += RAX;
            RAX = imageBase;
            RDX ^= RAX;
            return RDX;
        }
        case 9: {
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RDX += R8;
            RAX = imageBase;
            RDX += RAX;
            RAX = 0x89418BB77BA36B9;
            RDX += RAX;
            RAX = imageBase;
            RDX ^= RAX;
            RCX = 0x0;
            RAX = RDX;
            RCX = _rotl64(RCX, 0x10);
            RAX -= R8;
            RCX ^= RBX;
            RCX = _byteswap_uint64(RCX);
            RDX = readMemory<uint64_t>(RCX + 0xB);
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x4;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x8;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x10;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            RAX = 0xB2AE9D2D4DB6A90B;
            RDX *= RAX;
            return RDX;
        }
        case 10: {
            R14 = imageBase + 0x66CA;
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = imageBase;
            RDX ^= RAX;
            RDX += R8;
            RDX ^= R14;
            RDX ^= R8;
            RAX = RDX;
            RAX >>= 0x25;
            RDX ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RDX ^= R8;
            RDX ^= R8;
            RAX = 0x634FC37F4A4870CD;
            RDX *= RAX;
            return RDX;
        }
        case 11: {
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0xC0A066135A6A87D9;
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x1A;
            RDX ^= RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = RDX;
            RAX >>= 0x34;
            RCX ^= RBX;
            RAX ^= RDX;
            RCX = _byteswap_uint64(RCX);
            RAX ^= R8;
            RDX = readMemory<uint64_t>(RCX + 0xB);
            RDX *= RAX;
            RAX = imageBase;
            RDX ^= RAX;
            RCX = imageBase;
            RCX -= R8;
            RAX = 0x7D3FD8AC2ED99C0C;
            RDX += RAX;
            RDX += RCX;
            RAX = 0xEE53FCC459C43FC1;
            RDX *= RAX;
            return RDX;
        }
        case 12: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            R12 = imageBase + 0xF1B8;
            RAX = 0xD3E6C6C42C43709;
            RDX *= RAX;
            RAX = imageBase + 0x3F65;
            RAX = ~RAX;
            RAX += R8;
            RDX ^= RAX;
            RAX = R8;
            RAX = ~RAX;
            RAX += R12;
            RDX ^= RAX;
            return RDX;
        }
        case 13: {
            R14 = imageBase + 0xBFD5;
            R12 = imageBase + 0x37D7;
            R15 = imageBase + 0x2FEF;
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = R8 + R12;
            RDX ^= RAX;
            RCX = R15;
            RAX = RDX;
            RAX >>= 0x11;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x22;
            RAX ^= RDX;
            RDX = 0x6E2D9A996B2F4942;
            RCX *= R8;
            RDX += RAX;
            RDX += RCX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= RBX;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = 0x4206D1B9D97F0049;
            RDX *= RAX;
            RAX = R8;
            RAX = ~RAX;
            RAX *= R14;
            RDX += RAX;
            RAX = 0x3F9142075AC30CDC;
            RDX ^= RAX;
            return RDX;
        }
        case 14: {
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            R15 = imageBase + 0x7C40CAB0;
            R10 = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R10;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0x1D;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x3A;
            RDX ^= RAX;
            RAX = 0x67A237498CC6469A;
            RDX += RAX;
            RAX = imageBase;
            RDX ^= RAX;
            RAX = 0x71BA932BABDA2283;
            RDX *= RAX;
            RAX = R15;
            RAX *= R8;
            RDX += RAX;
            RAX = RDX;
            RAX >>= 0x1E;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x3C;
            RDX ^= RAX;
            return RDX;
        }
        case 15: {
            RBX = readMemory<uint64_t>(imageBase + 0x7435204);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= RBX;
            RAX = _byteswap_uint64(RAX);
            RDX *= readMemory<uint64_t>(RAX + 0xB);
            RAX = RDX;
            RAX >>= 0xB;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x16;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x2C;
            RDX ^= RAX;
            RCX = imageBase + 0x4C6A;
            RCX = ~RCX;
            RCX += RDX;
            RAX = 0xB14F914168F31401;
            RAX += RCX;
            RDX = RAX + R8 * 2;
            RAX = imageBase;
            RDX -= RAX;
            RAX = 0xF29B711648655D13;
            RDX *= RAX;
            RAX = 0x47EF3F4430075BA6;
            RDX ^= RAX;
            return RDX;
        }
        }
    }

    extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RBX = index;
        RCX = RBX * 0x13C8;
        RAX = 0xD012499B782A0FB3;
        RBX = imageBase;
        RAX = _umul128(RAX, RCX, &RDX);
        R10 = 0x702EE3992100CB55;
        RDX >>= 0xD;
        RAX = RDX * 0x275F;
        RCX -= RAX;
        RAX = 0x49FA94E5982F1A8D;
        R8 = RCX * 0x275F;
        RAX = _umul128(RAX, R8, &RDX);
        RDX >>= 0xC;
        RAX = RDX * 0x375E;
        R8 -= RAX;
        RAX = 0xB0CDD5E47968BD91;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R8;
        RCX = R8;
        RAX -= RDX;
        R8 &= 0x1;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0xD;
        RAX = RAX * 0x25DB;
        RCX -= RAX;
        RAX = R8 + RCX * 2;
        RAX = readMemory<uint16_t>(RBX + RAX * 2 + 0x74429C0);
        R8 = RAX * 0x13C8;
        RAX = R10;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R10;
        RDX >>= 0xC;
        RCX = RDX * 0x2483;
        R8 -= RCX;
        R9 = R8 * 0x412E;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0xC;
        RAX = RDX * 0x2483;
        R9 -= RAX;
        RAX = 0x32A2E2F92063B0AF;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = 0xAAAAAAAAAAAAAAAB;
        RDX >>= 0xA;
        RCX = RDX * 0x1439;
        RAX = _umul128(RAX, R9, &RDX);
        RDX >>= 0x1;
        RCX += RDX;
        RAX = RCX + RCX * 2;
        RAX += RAX;
        RCX = R9 * 8;
        RCX -= RAX;
        RSI = readMemory<uint16_t>(RCX + RBX + 0x744C130);
        return RSI;
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