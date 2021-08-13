#include "decryption.h"
#include "globals.h"
#include "offsets.h"
#include <stdlib.h>
#include "../driver/driver.h"

extern "C" auto decryption::decrypt_client_info(uint64_t imageBase, uint64_t peb) -> uint64_t
{
	uint64_t rax = imageBase, rcx = 0, rbx = 0, r8 = imageBase, rdx = 0, rbp = imageBase;
    rbx = driver::read<uint64_t>(imageBase + 0x17A3E1F8);
    if (rbx == 0)
        return 0;
 
    r8 = peb;
    r8 = ~r8;
    rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;// mov     rcx, [rbp+158h]
 
    rax = 0xFCED13C467C6698B; // mov     rax, 0FCED13C467C6698Bh
    rbx *= rax; // imul    rbx, rax
    rax = r8; // mov     rax, r8
    rdx = 0x3844E7F6ED3E15BC; // mov     rdx, 3844E7F6ED3E15BCh
    rax = ~rax; // not     rax
    rbx += rax; // add     rbx, rax
    rax = imageBase + 0x489FF96E; //lea     rax, cs:7FF6EBFAF96Eh - 7FF6A35B0000 = 489FF96E
    rax = ~rax; //not rax
    rbx += rax;//add rbx, rax
    rax = rbx;// mov rax,rbx
    rax >>= 0x17;// shr     rax, 17h
    rbx ^= rax;// xor     rbx, rax
    rax = imageBase + 0x43;// lea     rax, cs:7FF6A35B0043h = 43
    rcx -= rax;// sub     rcx, rax
    rax = rbx;//mov     rax, rbx
    rcx = 0; // and     rcx, 0FFFFFFFFC0000000h
    rax >>= 0x2E;// shr     rax, 2eh
    rax ^= rbx;// xor rax,rbx
    rcx = _rotl64(rcx, 0x10);// rol     rcx, 10h
    rcx ^= driver::read<uint64_t>(imageBase + 0x690110E);//xor     rcx, cs:qword_7FF6A9EB110E
    rax ^= rdx;//xor     rax, rdx
    rcx = _byteswap_uint64(rcx);//bswap   rcx
    rax += r8;// add rax,r8
    rbx = driver::read<uint64_t>(rcx + 0x15);// mov rbx, [rcx+15h]
    rbx *= rax;//imul rbx,rax
    return rbx;
}

extern "C" auto decryption::decrypt_client_base(uint64_t clientInfo, uint64_t imageBase, uint64_t peb) -> uint64_t
{
    uint64_t rax = imageBase, rbx = imageBase, rcx = imageBase, rdx = imageBase, r8 = imageBase, rdi = imageBase, rsi = imageBase, r9 = imageBase, r10 = imageBase, r11 = imageBase, r12 = imageBase, r13 = imageBase, r14 = imageBase, r15 = imageBase, ecx = imageBase, bnd0 = imageBase, rbp = imageBase;
    
    rax = driver::read<uint64_t>(clientInfo + 0x9DBE8);
    if (rax == 0)
        return 0;
    rbx = peb;

    rcx = rbx;
    rcx = _rotl64(rcx, 0x24);
    rcx &= 0xF;
    switch (rcx)
    {
    case 0:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        rcx = rax;
        rcx >>= 0x16;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x2C;
        rax ^= rcx;
        rcx = 0xB1234B0689FEED1;
        rax *= rcx;
        rcx = 0xD2BC4ACEA66D1E1B;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1F;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x3E;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1E;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x3C;
        rax ^= rcx;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rax -= r11;
        rdx -= rdi;
        rdx = 0; // Special case
        rdx = _rotl64(rdx, 0x10);
        rdx ^= r10;
        rdx = ~rdx;
        rcx = rbx + 0xFFFFFFFFCEA14AAA;
        rcx += rax;
        rcx ^= rbx;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        return rax;
    }
    case 1:
    {
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r9 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = r11 + 0xFB6F;
        rcx += rbx;
        rax ^= rcx;
        rax ^= rbx;
        rcx = rax;
        rcx >>= 0xE;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1C;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x38;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1F;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x3E;
        rax ^= rcx;
        rcx = 0x7B576C1A94E1013C;
        rax ^= rcx;
        rcx = 0x29C69418290CCE35;
        rax ^= rcx;
        rcx = 0x79FF5F0EEE20769;
        rax *= rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r9;
        rcx = ~rcx;
        rax *= driver::read<uint64_t>(rcx + 0x13);
        return rax;
    }
    case 2:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r14 = imageBase + 0x1861;
        r15 = imageBase + 0xA40A;
        rcx = rax;
        rcx >>= 0xA;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x14;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x28;
        rax ^= rcx;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rdx = 0; // Special case
        rcx = rbx;
        rcx *= r15;
        rdx = _rotl64(rdx, 0x10);
        rcx ^= rax;
        rdx ^= r10;
        rdx = ~rdx;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rcx = rax;
        rcx >>= 0x18;
        rax ^= rcx;
        rdx = rax;
        rdx >>= 0x30;
        rdx ^= rax;
        rax = rbx;
        rax *= r14;
        rax += rdx;
        rcx = 0x706402F41DE52AC9;
        rax *= rcx;
        rcx = 0xE602E1C4E2D078CB;
        rax ^= rcx;
        rcx = 0x458C07C6BDFE04F8;
        rax ^= rcx;
        return rax;
    }
    case 3:
    {
        rdi = imageBase + 0x523;
        r15 = imageBase + 0x4E080E42;
        r9 = driver::read<uint64_t>(imageBase + 0x690113D);
        rax -= rbx;
        rcx = rbx;
        rcx = ~rcx;
        rcx *= r15;
        rax ^= rcx;
        rcx = rbx;
        bnd0 = imageBase + 0x34E2;
        rcx *= bnd0;
        rax += rcx;
        rcx = imageBase + 0x6A3E82E2;
        rax += rcx;
        rcx = 0x6068B2883739B04F;
        rax *= rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r9;
        rcx = ~rcx;
        rax *= driver::read<uint64_t>(rcx + 0x13);
        rcx = rax;
        rcx >>= 0x9;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x12;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x24;
        rax ^= rcx;
        return rax;
    }
    case 4:
    {
        rdi = imageBase + 0x523;
        r14 = imageBase + 0xD8F;
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = rax;
        rcx >>= 0x19;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x32;
        rax ^= rcx;
        rax -= rbx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r10;
        rcx = ~rcx;
        rcx = driver::read<uint64_t>(rcx + 0x13);
        rax *= rcx;
        rcx = 0x4C2B84E0CBA297A4;
        rax += rcx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = r14;
        rcx -= rbx;
        rax ^= rcx;
        rcx = 0xBC823BB36FCCFC8F;
        rax *= rcx;
        rcx = rax;
        rcx >>= 0x21;
        rax ^= rcx;
        return rax;
    }
    case 5:
    {
        rdi = imageBase + 0x523;
        r11 = imageBase;
        rdx = imageBase + 0x13B45F2F;
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = rdx;
        rcx = ~rcx;
        rcx ^= rbx;
        rax -= rcx;
        /*rdx = read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;*/
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rdx = 0; // Special case
        rdx = _rotl64(rdx, 0x10);
        rcx = r11 + 0xA1A;
        rdx ^= r10;
        rcx += rbx;
        rdx = ~rdx;
        rdx = driver::read<uint64_t>(rdx + 0x13);
        rax *= rdx;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x2;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x4;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x8;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = 0x6D1F5C7319C7A591;
        rax ^= rcx;
        rcx = 0x6DFC846362600625;
        rax *= rcx;
        rcx = rax;
        rcx >>= 0x1C;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x38;
        rax ^= rcx;
        rcx = 0x456991416BCB2285;
        rax *= rcx;
        return rax;
    }
    case 6:
    {
        rdi = imageBase + 0x523;
        r14 = imageBase + 0x59621C27;
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = rax;
        rcx >>= 0x14;
        rax ^= rcx;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rcx = rax;
        rdx = 0; // Special case
        rcx >>= 0x28;
        rcx ^= rax;
        rdx = _rotl64(rdx, 0x10);
        rdx ^= r10;
        rdx = ~rdx;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rcx = 0xAB63115C0296DC39;
        rax *= rcx;
        rcx = rax;
        rcx >>= 0xB;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x16;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x2C;
        rax ^= rcx;
        rax ^= rbx;
        rcx = rbx;
        rcx = ~rcx;
        rcx *= r14;
        rax += rcx;
        rcx = 0x19E2C01FE567D3E5;
        rax += rcx;
        return rax;
    }
    case 7:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        rdx = imageBase + 0x4F18;
        rcx = rax;
        rcx >>= 0x21;
        rax ^= rcx;
        rax ^= rbx;
        rcx = 0x217CBC019ADD6CED;
        rax *= rcx;
        rcx = rbx + 0x1;
        rcx *= rdx;
        rax += rcx;
        rcx = 0xA975C5DE862ED14F;
        rax *= rcx;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rdx = 0; // Special case
        rcx = rax;
        rdx = _rotl64(rdx, 0x10);
        rax = 0x5C0E908CFA00E3B9;
        rcx ^= rax;
        rdx ^= r10;
        rdx = ~rdx;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rcx = r11 + 0x76725DFF;
        rcx += rbx;
        rax += rcx;
        return rax;
    }
    case 8:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rdx = 0; // Special case
        rdx = _rotl64(rdx, 0x10);
        rcx = rax;
        rdx ^= r10;
        rax = 0x826D4CD7053A3B0F;
        rdx = ~rdx;
        rcx ^= rax;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rdx = imageBase + 0x2566DC61;
        rax ^= r11;
        rcx = rax;
        rcx >>= 0x1D;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x3A;
        rax ^= rcx;
        rax -= rbx;
        rcx = 0x6E136F54C0304293;
        rax *= rcx;
        rcx = rbx;
        rcx *= rdx;
        rcx += r11;
        rax -= rcx;
        return rax;
    }
    case 9:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        rax ^= r11;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rax += rbx;
        rdx -= rdi;
        rdx = 0; // Special case
        rdx = _rotl64(rdx, 0x10);
        rcx = imageBase + 0x89E4;
        rax += rcx;
        rdx ^= r10;
        rdx = ~rdx;
        rcx = rax;
        rcx >>= 0x21;
        rcx ^= rax;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rcx = 0xA66D52587A5A7083;
        rax *= rcx;
        rax += r11;
        rcx = 0x640CAAE5A2282E05;
        rax ^= rcx;
        rcx = 0xF24051F81CDED63F;
        rax ^= rcx;
        return rax;
    }
    case 10:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r15 = imageBase + 0x4DB9D2C7;
        rcx = r15;
        rcx = ~rcx;
        rcx ^= rbx;
        rax += rcx;
        rcx = rax;
        rcx >>= 0x1B;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x36;
        rax ^= rcx;
        rcx = rbx;
        rcx -= r11;
        rax += rbx;
        rcx -= 0x78483513;
        rax ^= rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r10;
        rcx = ~rcx;
        rcx = driver::read<uint64_t>(rcx + 0x13);
        bnd0 = 0x57F82B1F124C3C35;
        rcx *= bnd0;
        rax *= rcx;
        rcx = 0x7F2AE5C1F19DABBD;
        rax ^= rcx;
        return rax;
    }
    case 11:
    {
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r9 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r9;
        rcx = ~rcx;
        rax *= driver::read<uint64_t>(rcx + 0x13);
        rcx = 0x5BD8DE6B9D51D117;
        rax += rcx;
        rcx = rax;
        rcx >>= 0x7;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0xE;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1C;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x38;
        rcx ^= rax;
        rax = 0x883E09AE2FC1878D;
        rcx ^= r11;
        rcx *= rax;
        rax = 0x376E32D2ACDB7105;
        rax += rcx;
        rax += rbx;
        rcx = rax;
        rcx >>= 0xA;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x14;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x28;
        rax ^= rcx;
        return rax;
    }
    case 12:
    {
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r9 = driver::read<uint64_t>(imageBase + 0x690113D);
        rcx = rax;
        rcx >>= 0x8;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = 0x4411B7D7BD0746A1;
        rax *= rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r9;
        rcx = ~rcx;
        rcx = driver::read<uint64_t>(rcx + 0x13);
        rax *= rcx;
        rcx = 0x374CACF0E3108651;
        rax -= r11;
        rax ^= rcx;
        rax ^= rbx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = 0x4E3C89CFA73560D5;
        rax *= rcx;
        return rax;
    }
    case 13:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r15 = imageBase + 0x1957CA6F;
        rcx = 0x7B7BDB1C95BBEB93;
        rax *= rcx;
        rax -= r11;
        rax += 0xFFFFFFFFFFFFFD6C;
        rax += rbx;
        rcx = 0x42A678B1F30FA0F3;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x12;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x24;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x1;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x2;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x4;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x8;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r10;
        rcx = ~rcx;
        rax *= driver::read<uint64_t>(rcx + 0x13);
        rcx = 0x1E3DEFA0B52408A8;
        rax += rcx;
        rcx = rbx;
        rcx *= r15;
        rax ^= rcx;
        return rax;
    }
    case 14:
    {
        r10 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdi = imageBase + 0x523;
        r11 = imageBase;
        r15 = imageBase + 0x2A03;
        rcx = r11 + 0xFA06;
        rcx += rbx;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x11;
        rax ^= rcx;
        rdx = driver::read<uint64_t>(rbp + 0x158); if (rdx == 0) rdx = imageBase;
        rdx -= rdi;
        rdx = 0; // Special case
        rdx = _rotl64(rdx, 0x10);
        rcx = rax;
        rdx ^= r10;
        rcx >>= 0x22;
        rdx = ~rdx;
        rcx ^= rax;
        rax = driver::read<uint64_t>(rdx + 0x13);
        rax *= rcx;
        rcx = 0xF3E6DE9C18BDD449;
        rax *= rcx;
        rax ^= rbx;
        rax ^= r15;
        rcx = 0x4439F2BD595FD830;
        rax ^= rcx;
        rcx = 0x756C97787209CC0;
        rax -= rcx;
        rcx = rax;
        rcx >>= 0x26;
        rax ^= rcx;
        return rax;
    }
    case 15:
    {
        rdi = imageBase + 0x523;
        r14 = imageBase + 0x3D88;
        r15 = imageBase + 0x5DA;
        r11 = driver::read<uint64_t>(imageBase + 0x690113D);
        rdx = r15;
        rdx = ~rdx;
        rcx = rbx + 0x1;
        rcx *= r14;
        rcx += rax;
        rax = rbx + 0x1;
        rdx += rcx;
        rcx = 0x9FA0F66FBCE5D1B8;
        rax += rdx;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x10;
        rax ^= rcx;
        rcx = rax;
        rcx >>= 0x20;
        rax ^= rcx;
        rcx = 0x1F8175F85982B5D5;
        rax += rcx;
        rcx = driver::read<uint64_t>(rbp + 0x158); if (rcx == 0) rcx = imageBase;
        rcx -= rdi;
        rcx = 0; // Special case
        rcx = _rotl64(rcx, 0x10);
        rcx ^= r11;
        rcx = ~rcx;
        rax *= driver::read<uint64_t>(rcx + 0x13);
        rcx = 0x6FBF45724BDD188F;
        rax *= rcx;
        rax ^= rbx;
        return rax;
    }
    }
    return 0;
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