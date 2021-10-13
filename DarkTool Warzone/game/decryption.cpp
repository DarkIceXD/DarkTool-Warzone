#include "decryption.h"
#include "globals.h"
#include <stdlib.h>
#include "../driver/driver.h"

#define readMemory driver::read

namespace decryption {
    extern "C" auto decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase;

        RBX = readMemory<uint64_t>(imageBase + 0x17E21C88);
        if (RBX == 0) {
            return 0;
        }
        RAX ^= 0xFFFFFFFFFFFFFFF8;
        // movzx eax,al
        RCX = peb; // mov rcx,gs:[rax]
        RAX = 0x214C49CDB728D2B5;
        RBX *= RAX;
        RAX = 0x507343EDDC5832C3;
        RCX *= RAX;
        RBX -= RCX;
        RAX = RBX;
        RAX >>= 0x20;
        RCX = 0x0;
        RAX ^= RBX;
        RCX = _rotl64(RCX, 0x10);
        RCX ^= readMemory<uint64_t>(imageBase + 0x71BC0E7);
        RCX = ~RCX;
        RBX = readMemory<uint64_t>(RCX + 0x13);
        RBX *= RAX;
        RAX = RBX;
        RAX >>= 0x16;
        RBX ^= RAX;
        RAX = RBX;
        RAX >>= 0x2C;
        RBX ^= RAX;
        return RBX;
    }

    extern "C" auto decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RAX = readMemory<uint64_t>(clientInfo + 0x9FE28);
        RBX = peb; // mov rbx,gs:[rcx]
        // test rax,rax
        // je 00007FF6A9BA6781h
        RCX = RBX;
        RCX >>= 0x11;
        RCX &= 0xF;
        // cmp rcx,0Eh
        // ja 00007FF6A9BA6280h
        switch (RCX) {
        case 0: {
            R15 = imageBase + 0x3AFF88A4;
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            RCX = 0xC0E9A3A6540931BF;
            RAX *= RCX;
            RCX = RBX;
            RCX *= R15;
            RAX ^= RCX;
            RCX = imageBase + 0x1DFE;
            RCX = ~RCX;
            RCX += RAX;
            RAX = RBX + 1;
            RAX += RCX;
            RCX = 0x7695DF4B729D5843;
            RAX -= RCX;
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
            RAX += RBX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            return RAX;
        }
        case 1: {
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = 0x1A58DEC973C787A9;
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
            RCX = imageBase + 0xCB6C;
            RCX = ~RCX;
            RCX -= RBX;
            RAX += RCX;
            RAX += RBX;
            RCX = 0x1D272B3383179E3A;
            RAX -= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = 0x80E5552DE663C649;
            RAX *= RCX;
            RDX = RBX;
            RDX = ~RDX;
            RCX = imageBase + 0x60494D59;
            RCX = ~RCX;
            RDX *= RCX;
            RAX += RDX;
            return RAX;
        }
        case 2: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = 0x1CBB8F41D24CF63A;
            RAX -= RCX;
            RCX = 0x19F47B9BC24F30D5;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x15;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2A;
            RAX ^= RCX;
            RAX -= R11;
            RAX += 0xFFFFFFFFFFFF65B7;
            RAX += RBX;
            RCX = R11 + 0x0B2;
            RCX += RBX;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RAX += RBX;
            RAX -= R11;
            return RAX;
        }
        case 3: {
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            R11 = imageBase;
            RAX -= R11;
            RAX += 0xFFFFFFFFCDB72AC0;
            RAX += RBX;
            RAX -= R11;
            RAX += 0xFFFFFFFFEA77B5BE;
            RAX += RBX;
            RCX = 0x658DBC7F2E66D7DD;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x13;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x26;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = RAX;
            RCX >>= 0x21;
            RAX ^= RCX;
            RCX = 0xC6F59BF67AA8759;
            RAX += RCX;
            RCX = imageBase + 0x326F56BE;
            RCX -= RBX;
            RAX += RCX;
            return RAX;
        }
        case 4: {
            uint64_t RSP_0x60 = imageBase;
            R14 = imageBase + 0x63A0;
            RCX = imageBase + 0x36E4B0E2;
            RSP_0x60 = RCX; // mov [rsp+60h],rcx
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = 0x7E08AF8C0C84CCCF;
            RAX *= RCX;
            RCX = 0xF1E331FE13522CE0;
            RAX ^= RCX;
            RCX = RBX;
            RCX = ~RCX;
            RCX *= RSP_0x60; // imul rcx,[rsp+60h]
            RAX = RAX + RCX * 2;
            RCX = R14;
            RCX = ~RCX;
            RAX ^= RCX;
            RAX ^= RBX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = RAX;
            RCX >>= 0x22;
            RAX ^= RCX;
            return RAX;
        }
        case 5: {
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            R11 = imageBase;
            RCX = 0xC610A7703947AF61;
            RAX *= RCX;
            RCX = 0x1FDF97CF08CF052C;
            RAX += RCX;
            RAX -= RBX;
            RCX = 0x3125CA5D1FA4F649;
            RAX *= RCX;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RCX = RBX;
            RCX -= R11;
            RDX ^= R10;
            RCX -= 0x521FDFD6;
            RCX ^= RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x19;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x32;
            RAX ^= RCX;
            return RAX;
        }
        case 6: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RAX ^= RBX;
            RAX ^= R11;
            RCX = 0xCA6260EB0A322085;
            RAX *= RCX;
            RCX = 0x19BD4A90DEC6A138;
            RAX += RCX;
            RCX = RAX;
            RCX >>= 0x17;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x2E;
            RAX ^= RCX;
            RAX -= RBX;
            RCX = 0x9EEA5457D5AC8FF9;
            RAX *= RCX;
            return RAX;
        }
        case 7: {
            uint64_t RSP_0x78 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = imageBase + 0x23D3;
            RSP_0x78 = RCX; // mov [rsp+78h],rcx
            RCX = RAX;
            RCX >>= 0x10;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x20;
            RAX ^= RCX;
            RCX = 0x11DDF0D1E502F8EE;
            RAX += RCX;
            RDX = 0x0;
            RCX = RBX;
            RCX ^= RSP_0x78; // xor rcx,[rsp+78h]
            RCX += RAX;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = 0x301DD3778A9D2305;
            RAX *= RCX;
            RDX = 0x1;
            RCX = imageBase + 0x3F8AB254;
            RDX -= RCX;
            RCX = imageBase + 0x76DA;
            RDX *= RBX;
            RAX += RCX;
            RAX += RDX;
            RCX = 0xF1828C19C82517B1;
            RAX ^= RCX;
            return RAX;
        }
        case 8: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = RAX;
            RCX >>= 0x19;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x32;
            RAX ^= RCX;
            RAX = RAX + RBX * 2;
            RCX = RAX;
            RCX >>= 0xC;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x18;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x30;
            RAX ^= RCX;
            RCX = 0xB6E10303D890A57B;
            RAX *= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RCX = 0x3FE72862B858B77E;
            RAX += RCX;
            return RAX;
        }
        case 9: {
            uint64_t RSP_0x70 = imageBase;
            RCX = 0x576D32ECAA11DD87;
            RSP_0x70 = RCX; // mov [rsp+70h],rcx
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = R11 + 0x7D018F4C;
            RCX += RBX;
            RAX ^= RCX;
            RCX = 0x7554DE5D407A6456;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RCX *= RSP_0x70; // imul rcx,[rsp+70h]
            RAX *= RCX;
            RAX += RBX;
            RAX ^= RBX;
            RCX = RAX;
            RCX >>= 0xA;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RAX -= RBX;
            return RAX;
        }
        case 10: {
            uint64_t RSP_0x70 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = imageBase + 0x4FAC8CB6;
            RSP_0x70 = RCX; // mov [rsp+70h],rcx
            R11 = imageBase;
            R15 = imageBase + 0x6BEACA00;
            RCX = R15;
            RCX = ~RCX;
            RCX *= RBX;
            RAX ^= RCX;
            RCX = 0x1FA72118CFEEFA4B;
            RAX *= RCX;
            RCX = 0x4BC792C4FB7E01BD;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x14;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x28;
            RAX ^= RCX;
            RCX = 0x4C2A25BE395B47B;
            RAX -= RCX;
            RCX = RBX;
            RCX = ~RCX;
            RCX *= RSP_0x70; // imul rcx,[rsp+70h]
            RCX -= R11;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            return RAX;
        }
        case 11: {
            R11 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RAX += RBX;
            RCX = 0x9642BC5E055C0633;
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x19;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x32;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            RAX -= R11;
            RCX = RAX;
            RCX >>= 0x1D;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3A;
            RAX ^= RCX;
            RCX = 0x27C8FD523C1B5CB9;
            RAX *= RCX;
            RCX = 0x5E06D9AAEC77AD67;
            RAX -= RCX;
            return RAX;
        }
        case 12: {
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            R11 = imageBase;
            R15 = imageBase + 0x52EDA6B4;
            RDX = imageBase + 0x1E3;
            RCX = R15;
            RCX = ~RCX;
            RCX += RBX;
            RAX += RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R10;
            RCX = _byteswap_uint64(RCX);
            RCX = readMemory<uint64_t>(RCX + 0x9);
            RAX *= RCX;
            RCX = 0xF4CC067F544E69F4;
            RAX ^= RCX;
            RCX = 0xFC6B620BDD33887F;
            RAX *= RCX;
            RCX = RBX;
            RCX ^= RDX;
            RAX += RCX;
            RAX -= R11;
            RAX += 0xFFFFFFFF84DD095C;
            RAX += RBX;
            RCX = RAX;
            RCX >>= 0x8;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x10;
            RAX ^= RCX;
            RCX = imageBase + 0x2A1DCBFD;
            RDX = RAX;
            RDX >>= 0x20;
            RDX ^= RAX;
            RAX = RBX;
            RAX = ~RAX;
            RAX += RDX;
            RAX += RCX;
            return RAX;
        }
        case 13: {
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            R11 = imageBase;
            R15 = imageBase + 0xEDD2;
            RDX = 0x0;
            RDX = _rotl64(RDX, 0x10);
            RDX ^= R10;
            RCX = R15;
            RCX = ~RCX;
            RCX -= RBX;
            RCX ^= RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RAX -= RBX;
            RCX = RAX;
            RCX >>= 0xE;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1C;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x38;
            RAX ^= RCX;
            RCX = 0x753C67282D01BB89;
            RAX *= RCX;
            RCX = 0x25411E2B6A01E9C2;
            RAX ^= RCX;
            RCX = 0xFF3AE2D86FD8A3B5;
            RAX *= RCX;
            RAX += R11;
            return RAX;
        }
        case 14: {
            uint64_t RSP_0x70 = imageBase;
            R10 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = imageBase + 0x120984FB;
            RSP_0x70 = RCX; // mov [rsp+70h],rcx
            R11 = imageBase;
            RCX = RAX;
            RCX >>= 0xF;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1E;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3C;
            RAX ^= RCX;
            RCX = 0x3871C568D91619BB;
            RAX *= RCX;
            RCX = 0xF95E4F932BE1479D;
            RAX ^= RCX;
            RAX += R11;
            RCX = 0x5423B8F4E60ACF6A;
            RAX ^= RCX;
            RDX = 0x0;
            RCX = RBX;
            RCX = ~RCX;
            RDX = _rotl64(RDX, 0x10);
            RCX += RSP_0x70; // add rcx,[rsp+70h]
            RDX ^= R10;
            RCX ^= RAX;
            RDX = _byteswap_uint64(RDX);
            RAX = readMemory<uint64_t>(RDX + 0x9);
            RAX *= RCX;
            RCX = RAX;
            RCX >>= 0x1F;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x3E;
            RAX ^= RCX;
            return RAX;
        }
        case 15: {
            R14 = imageBase + 0xB4A0;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC127);
            RCX = RBX;
            RCX ^= R14;
            RAX += RCX;
            RCX = RAX;
            RCX >>= 0x9;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x12;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x24;
            RAX ^= RCX;
            RCX = 0xD03CF3E809D30498;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x1B;
            RAX ^= RCX;
            RCX = RAX;
            RCX >>= 0x36;
            RAX ^= RCX;
            RAX += RBX;
            RCX = 0xC21C274236179BE9;
            RAX *= RCX;
            RCX = 0x92304A35AE0B0ACC;
            RAX ^= RCX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = _byteswap_uint64(RCX);
            RAX *= readMemory<uint64_t>(RCX + 0x9);
            return RAX;
        }
        }
    }

    extern "C" auto decrypt_bone_base(uint64_t imageBase, uint64_t peb) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RDX = readMemory<uint64_t>(imageBase + 0x15BE3AB8);
        if (RDX == 0) {
            return 0;
        }
        R11 = peb; // mov r11,gs:[rax]
        // test rdx,rdx
        // je 00007FF6A9D1724Ah
        RAX = R11;
        RAX >>= 0x14;
        RAX &= 0xF;
        // cmp rax,0Eh
        // ja 00007FF6A9D16BCCh
        switch (RAX) {
        case 0: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            R12 = imageBase + 0x380B4B43;
            R15 = imageBase + 0x403CC046;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RAX = 0x220D2673D1ABB8FA;
            RDX += RAX;
            RAX = 0x5F428DB50197FFE;
            RDX -= RAX;
            RAX = RDX;
            RAX >>= 0x17;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x2E;
            RDX ^= RAX;
            RCX = R11;
            RCX = ~RCX;
            RCX ^= R12;
            RAX = RDX;
            RDX = 0xE1AD2B250F9E3ADB;
            RDX *= RAX;
            RDX += RCX;
            RAX = R11 + 1;
            RAX *= R15;
            RDX += RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = RDX;
            RAX >>= 0x10;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            return RDX;
        }
        case 1: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
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
            RCX = 0x0;
            RAX >>= 0x20;
            RAX ^= RDX;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            RDX += R10;
            RAX = 0xDAE7FECF6D55B18E;
            RDX += RAX;
            RDX += R10;
            RAX = RDX;
            RAX >>= 0xC;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x18;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x30;
            RDX ^= RAX;
            RAX = 0x9A66454300C8B96;
            RDX ^= RAX;
            RAX = 0x2604905E6A63EEB;
            RDX *= RAX;
            return RDX;
        }
        case 2: {
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            RAX = 0x4724B474EFEB4305;
            RDX *= RAX;
            RDX += R11;
            RAX = imageBase + 0x2C183CC7;
            RDX += RAX;
            RDX ^= R10;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = 0x2481F0F4B092397B;
            RDX += RAX;
            RAX = imageBase + 0x5342;
            RAX = ~RAX;
            RAX *= R11;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x1B;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x36;
            RDX ^= RAX;
            RAX = 0x5962DF6F257C6450;
            RDX ^= RAX;
            return RDX;
        }
        case 3: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R12 = imageBase + 0x3AFA1F2F;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x13;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x26;
            RDX ^= RAX;
            RAX = 0xAE6B6B8F9AE97D2F;
            RAX *= RDX;
            RDX = 0x71ABF04BF3A605C0;
            RAX -= RDX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            RAX = R12;
            RAX = ~RAX;
            RAX += R11;
            RDX += RAX;
            RAX = 0x348E3B81B73DC393;
            RDX *= RAX;
            RDX -= R11;
            return RDX;
        }
        case 4: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            RDX -= R10;
            RAX = 0xF5B8D30833C5B141;
            RDX += RAX;
            RDX += R10;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = RDX;
            RAX >>= 0x9;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x12;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x24;
            RDX ^= RAX;
            RAX = 0xE4F7F9CE9154DE55;
            RDX *= RAX;
            RAX = 0x132D2020B99CFCCE;
            RDX -= RAX;
            RAX = RDX;
            RAX >>= 0x8;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x10;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x20;
            RDX ^= RAX;
            return RDX;
        }
        case 5: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            RAX = RDX;
            RAX >>= 0x1E;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x3C;
            RDX ^= RAX;
            RCX = 0x0;
            RAX = imageBase + 0x6530;
            RAX -= R11;
            RCX = _rotl64(RCX, 0x10);
            RAX ^= R11;
            RCX ^= R9;
            RAX ^= RDX;
            RCX = ~RCX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            RAX = R11;
            RAX -= R10;
            RAX += 0xFFFFFFFFFFFF5890;
            RDX += RAX;
            RAX = 0x73841ABD241808F7;
            RDX ^= RAX;
            RAX = 0xC9B4C235F1583167;
            RDX *= RAX;
            RAX = 0x2B85C623FA29A4E2;
            RDX += RAX;
            return RDX;
        }
        case 6: {
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            R8 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R8;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = RDX;
            RAX >>= 0xA;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x14;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x28;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x27;
            RDX ^= RAX;
            RAX = 0xB2ABDAA49B72336B;
            RDX *= RAX;
            RAX = 0xBAA66D753AD5EDB8;
            RDX ^= RAX;
            RDX ^= R11;
            RDX -= R11;
            RAX = 0x3207C325402B41DD;
            RDX ^= RAX;
            return RDX;
        }
        case 7: {
            R10 = imageBase;
            R8 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RAX = 0x7CE1BAB578C00819;
            RDX *= RAX;
            RAX = 0x97969E0ACAD77001;
            RDX += R11;
            RDX += RAX;
            RDX += R10;
            RDX ^= R10;
            RDX += R11;
            RAX = R10 + 0x110BDFDD;
            RAX += R11;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x1C;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x38;
            RDX ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R8;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            return RDX;
        }
        case 8: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            R15 = imageBase + 0x3635500B;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = RDX;
            RAX >>= 0x11;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x22;
            RDX ^= RAX;
            RAX = imageBase + 0x9EBC;
            RAX = ~RAX;
            RAX += R11;
            RDX ^= RAX;
            RAX = 0x936009C8330CFD8D;
            RDX *= RAX;
            RAX = 0x4437E40A18A116BC;
            RDX += RAX;
            RAX = R11;
            RDX ^= R10;
            RAX = ~RAX;
            RAX *= R15;
            RDX += RAX;
            RDX -= R10;
            return RDX;
        }
        case 9: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            R13 = imageBase + 0x4D4B8D68;
            RAX = R11;
            RAX ^= R13;
            RAX += RDX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            RDX ^= R10;
            RAX = 0x6D53459E0863A7F3;
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0xA;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x14;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x28;
            RDX ^= RAX;
            RAX = 0xB83D740F3C1FC29E;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0xA;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x14;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x28;
            RDX ^= RAX;
            RDX -= R10;
            return RDX;
        }
        case 10: {
            R15 = imageBase + 0x270717E7;
            R14 = imageBase + 0x3201;
            R8 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RAX = R11;
            RAX *= R15;
            RDX ^= RAX;
            RAX = 0xD4DDC016170C075B;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x19;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x32;
            RDX ^= RAX;
            RAX = 0x937221F5F42CD8F1;
            RDX *= RAX;
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
            RAX ^= R11;
            RDX ^= RAX;
            RDX ^= R14;
            RAX = RDX;
            RAX >>= 0x15;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x2A;
            RDX ^= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R8;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            return RDX;
        }
        case 11: {
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            R12 = imageBase + 0x722D200E;
            RDX -= R10;
            RCX = RDX;
            RAX = R11;
            RAX ^= R12;
            RCX >>= 0x25;
            RDX ^= RCX;
            RDX -= RAX;
            RAX = 0xCAA5D39A4A8BFC05;
            RDX *= RAX;
            RAX = 0x54EAAC9C2872F815;
            RDX *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R9;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RAX = R11;
            RAX = ~RAX;
            RAX -= R10;
            RAX -= 0x480F;
            RDX ^= RAX;
            RAX = 0x4BD31737F4D03E21;
            RDX ^= RAX;
            return RDX;
        }
        case 12: {
            // push rdx
            // pushfq
            // pop rdx
            // popfq
            // pop rdx
            R10 = imageBase;
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RAX = RDX;
            RAX >>= 0x9;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x12;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x24;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x12;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x24;
            RDX ^= RAX;
            RAX = 0xB68E7574BC1B754B;
            RDX += R10;
            RDX ^= RAX;
            RDX += R11;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RAX = 0xD43D837CAA5A532B;
            RAX *= RDX;
            RCX ^= R9;
            RDX = 0x26517B6E97146804;
            RCX = ~RCX;
            RAX += RDX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            return RDX;
        }
        case 13: {
            R10 = imageBase;
            R8 = readMemory<uint64_t>(imageBase + 0x71BC226);
            RDX -= R10;
            RAX = R10 + 0x7273CF02;
            RAX += R11;
            RDX ^= RAX;
            RAX = 0x87D5AC121B8A3BE9;
            RDX *= RAX;
            RAX = 0x0;
            RAX = _rotl64(RAX, 0x10);
            RAX ^= R8;
            RAX = ~RAX;
            RDX *= readMemory<uint64_t>(RAX + 0x5);
            RDX ^= R10;
            RAX = RDX;
            RAX >>= 0x23;
            RDX ^= RAX;
            RDX ^= R10;
            return RDX;
        }
        case 14: {
            // pushfq
            // push rdx
            // pop rdx
            // pop rdx
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            R15 = imageBase + 0x173D;
            R14 = imageBase + 0x50774E73;
            RAX = 0x1774DCA2AF934A3F;
            RDX *= RAX;
            RCX = R14;
            RCX = ~RCX;
            RCX += R11;
            RAX = RDX;
            RAX -= R10;
            RDX = RCX;
            RDX ^= RAX;
            RCX = 0x0;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RAX = R11;
            RAX ^= RDX;
            RCX = ~RCX;
            RAX ^= R15;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
            RAX = 0xF745AEA0F274A07;
            RDX += RAX;
            RAX = 0x5ED9184D9FB060C3;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x25;
            RDX ^= RAX;
            return RDX;
        }
        case 15: {
            // pop rdx
            // pop rdx
            R9 = readMemory<uint64_t>(imageBase + 0x71BC226);
            R10 = imageBase;
            RAX = RDX;
            RAX >>= 0x14;
            RDX ^= RAX;
            RAX = RDX;
            RAX >>= 0x28;
            RCX = 0x0;
            RAX ^= RDX;
            RCX = _rotl64(RCX, 0x10);
            RCX ^= R9;
            RCX = ~RCX;
            RDX = readMemory<uint64_t>(RCX + 0x5);
            RDX *= RAX;
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
            RAX = 0x3412D996E1F1EED5;
            RDX *= RAX;
            RAX = RDX;
            RAX >>= 0x14;
            RDX ^= RAX;
            RCX = R10 + 0x8DB4;
            RCX += R11;
            RAX = RDX;
            RAX >>= 0x28;
            RCX ^= RAX;
            RDX ^= RCX;
            RAX = R11;
            RAX -= R10;
            RAX -= 0x17053EAF;
            RDX ^= RAX;
            RDX ^= R10;
            return RDX;
        }
        }
    }

    extern "C" auto get_bone_index(uint32_t index, uint64_t imageBase) -> uint64_t
    {
        uint64_t RAX = imageBase, RBX = imageBase, RCX = imageBase, RDX = imageBase, R8 = imageBase, RDI = imageBase, RSI = imageBase, R9 = imageBase, R10 = imageBase, R11 = imageBase, R12 = imageBase, R13 = imageBase, R14 = imageBase, R15 = imageBase, RBP = 0, RSP = 0;

        RBX = index;
        RCX = RBX * 0x13C8;
        RAX = 0xF8BE336FD4C2F01;
        R11 = imageBase;
        RAX = _umul128(RAX, RCX, &RDX);
        R10 = 0x586A9F01B9489BBB;
        RDX >>= 0x9;
        RAX = RDX * 0x20EF;
        RCX -= RAX;
        RAX = 0x1150D721215493BD;
        R8 = RCX * 0x20EF;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = R8;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0xD;
        RAX = RAX * 0x3BF2;
        R8 -= RAX;
        RAX = 0xE38E38E38E38E38F;
        RAX = _umul128(RAX, R8, &RDX);
        RAX = 0x15390948F40FEAC7;
        RDX >>= 0x7;
        RCX = RDX + RDX * 8;
        RAX = _umul128(RAX, R8, &RDX);
        RCX <<= 0x4;
        RDX >>= 0x4;
        RCX += RDX;
        RAX = RCX * 0x182;
        RCX = R8 * 0x184;
        RCX -= RAX;
        RAX = readMemory<uint16_t>(RCX + R11 + 0x71C8530);
        R8 = RAX * 0x13C8;
        RAX = R10;
        RAX = _umul128(RAX, R8, &RDX);
        RCX = R8;
        RAX = R10;
        RCX -= RDX;
        RCX >>= 0x1;
        RCX += RDX;
        RCX >>= 0xC;
        RCX = RCX * 0x17C9;
        R8 -= RCX;
        R9 = R8 * 0x2D5F;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = R9;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0xC;
        RAX = RAX * 0x17C9;
        R9 -= RAX;
        RAX = 0xCA95906B9F74B92D;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = 0x2492492492492493;
        RDX >>= 0xA;
        RCX = RDX * 0x50E;
        RAX = _umul128(RAX, R9, &RDX);
        RAX = R9;
        R9 <<= 0x4;
        RAX -= RDX;
        RAX >>= 0x1;
        RAX += RDX;
        RAX >>= 0x2;
        RCX += RAX;
        RAX = RCX * 0xE;
        R9 -= RAX;
        RSI = readMemory<uint16_t>(R9 + R11 + 0x71D5E50);
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