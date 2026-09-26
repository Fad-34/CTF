// Vault.cpp
//
// Faithful single-file restoration of the original CTF binary, with all
// functions placed in their ORIGINAL ADDRESS ORDER as they appeared in
// the Hex-Rays output (the "//----- (address) -----" markers), rather
// than grouped by pattern. This means the three real functions
// (djjsdjslksa, L019837, L333) are scattered among the L0001-L0100
// decoys exactly where they sat in the binary:
//
//   djjsdjslksa   addr 0x2669   -- right before L0001
//   L019837       addr 0x68DE   -- between L0093 and L0094
//   L333          addr 0x711C   -- between L0100 and L_touch_all
//
// main() is restored to match the ORIGINAL behavior exactly: it only
// prints "What is NADI?" and returns. It does NOT call L333() -- that
// path is unreachable dead code, same as in the shipped binary.
//
// Not reproduced: sub_2020..sub_22C0 (PLT/dynamic-linker jump stubs --
// linker artifacts, not application source; a normal build regenerates
// its own PLT automatically).
//
// Build:
//   g++ -std=c++17 -O2 -Wall -o Private Vault.cpp -lcrypto
//
// Run:
//   ./Private

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>

// ---- djjsdjslksa (addr 0x2669, right before L0001) --------------------
// djjsdjslksa(): decode a hex-ASCII string into raw bytes.
std::vector<unsigned char> djjsdjslksa(const std::string &a2)
{
    std::vector<unsigned char> a1;
    a1.reserve(a2.size() / 2);

    for (size_t i = 0; i + 1 < a2.size(); i += 2)
    {
        std::string byteStr = a2.substr(i, 2);
        unsigned char b = static_cast<unsigned char>(
            std::strtol(byteStr.c_str(), nullptr, 16));
        a1.push_back(b);
    }
    return a1;
}

// ---- L0001 ----
int64_t L0001(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 11; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0002 ----
std::string L0002(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 1) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0003 ----
int64_t L0003(int32_t a1)
{
    if (a1 <= 0)
        return 4;
    if (a1 <= 8)
        return a1 * (uint32_t)L0003(a1 - 1) + 8;
    return L0003(a1 % 8);
}

// ---- L0004 ----
uint64_t L0004(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 6; ++i)
        v9.push_back((double)i * a1 - 0.14);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0005 ----
int64_t L0005(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x2A3D)) | 0xBD) - ((16 * a1 + (a1 ^ (uint32_t)0x2A3D)) >> 2);
}

// ---- L0006 ----
int64_t L0006(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 3 * a1 - a1 % 9);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (3 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0007 ----
int64_t L0007(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 8) return 36;
    if (v1 > 8) return (int64_t)(uint32_t)-4;
    if (v1 == 3) return 2;
    if (v1 > 3) return (int64_t)(uint32_t)-4;
    if (v1 != 0) {
        if (v1 != 1) return (int64_t)(uint32_t)-4;
        return 39;
    }
    return 33;
}

// ---- L0008 ----
int64_t L0008(int32_t a1)
{
    return ((((92 * a1) ^ 0x150) - 2) >> 3) ^ (((92 * a1) ^ 0x150u) - 2);
}

// ---- L0009 ----
int64_t L0009(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 38; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0010 ----
std::string L0010(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 14) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0011 ----
int64_t L0011(int32_t a1)
{
    if (a1 <= 0)
        return 7;
    if (a1 <= 4)
        return a1 * (uint32_t)L0011(a1 - 1) + 19;
    return L0011(a1 % 4);
}

// ---- L0012 ----
uint64_t L0012(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 7; ++i)
        v9.push_back((double)i * a1 - 0.8090000000000001);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0013 ----
int64_t L0013(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x11A9)) | 0xD2) - ((16 * a1 + (a1 ^ (uint32_t)0x11A9)) >> 2);
}

// ---- L0014 ----
int64_t L0014(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 4 * a1 - a1 % 9);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (4 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0015 ----
int64_t L0015(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 6) return 25;
    if (v1 > 6) return (int64_t)(uint32_t)-2;
    if (v1 == 4) return 22;
    if (v1 > 4) return (int64_t)(uint32_t)-2;
    if (v1 == 2) return 7;
    if (v1 != 3) return (int64_t)(uint32_t)-2;
    return 6;
}

// ---- L0016 ----
int64_t L0016(int32_t a1)
{
    return ((((46 * a1) ^ 0xB4) + 128) >> 3) ^ (((46 * a1) ^ 0xB4u) + 128);
}

// ---- L0017 ----
int64_t L0017(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 20; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0018 ----
std::string L0018(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 2) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0019 ----
int64_t L0019(int32_t a1)
{
    if (a1 <= 0)
        return 7;
    if (a1 <= 8)
        return a1 * (uint32_t)L0019(a1 - 1) + 18;
    return L0019(a1 % 8);
}

// ---- L0020 ----
uint64_t L0020(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 4; ++i)
        v9.push_back((double)i * a1 - 0.973);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0021 ----
int64_t L0021(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x70E7)) | 0x24) - ((16 * a1 + (a1 ^ (uint32_t)0x70E7)) >> 2);
}

// ---- L0022 ----
int64_t L0022(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 6 * a1 - a1 % 8);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (6 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0023 ----
int64_t L0023(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 5) return 6;
    if (v1 > 5) return (int64_t)(uint32_t)-4;
    if (v1 == 3) return 15;
    if (v1 > 3) return (int64_t)(uint32_t)-4;
    if (v1 != 0) {
        if (v1 != 1) return (int64_t)(uint32_t)-4;
        return 50;
    }
    return 19;
}

// ---- L0024 ----
int64_t L0024(int32_t a1)
{
    return ((((13 * a1) ^ 0xC4) + 23) >> 3) ^ (((13 * a1) ^ 0xC4u) + 23);
}

// ---- L0025 ----
int64_t L0025(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 33; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0026 ----
std::string L0026(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 21) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0027 ----
int64_t L0027(int32_t a1)
{
    if (a1 <= 0)
        return 2;
    if (a1 <= 5)
        return a1 * (uint32_t)L0027(a1 - 1) + 12;
    return L0027(a1 % 5);
}

// ---- L0028 ----
uint64_t L0028(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 8; ++i)
        v9.push_back((double)i * a1 - 0.21);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0029 ----
int64_t L0029(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x5458)) | 0xC3) - ((16 * a1 + (a1 ^ (uint32_t)0x5458)) >> 2);
}

// ---- L0030 ----
int64_t L0030(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 3 * a1 - a1 % 5);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (3 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0031 ----
int64_t L0031(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 9) return 36;
    if (v1 <= 9) {
        if (v1 == 7) return 45;
        if (v1 <= 7) {
            if (v1 == 2) return 41;
            if (v1 == 3) return 18;
        }
    }
    return (int64_t)(uint32_t)-4;
}

// ---- L0032 ----
int64_t L0032(int32_t a1)
{
    return ((((88 * a1) ^ 0xA8) + 11) >> 3) ^ (((88 * a1) ^ 0xA8u) + 11);
}

// ---- L0033 ----
int64_t L0033(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 7; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0034 ----
std::string L0034(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 8) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0035 ----
int64_t L0035(int32_t a1)
{
    if (a1 <= 0)
        return 5;
    if (a1 <= 3)
        return a1 * (uint32_t)L0035(a1 - 1) + 13;
    return L0035(a1 % 3);
}

// ---- L0036 ----
uint64_t L0036(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 7; ++i)
        v9.push_back((double)i * a1 - 0.066);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0037 ----
int64_t L0037(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0xF9C3)) | 0xA1) - ((16 * a1 + (a1 ^ (uint32_t)0xF9C3)) >> 2);
}

// ---- L0038 ----
int64_t L0038(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 7 * a1 - a1 % 6);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (7 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0039 ----
int64_t L0039(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 8) return 36;
    if (v1 <= 8) {
        if (v1 == 7) return 16;
        if (v1 <= 7) {
            if (v1 == 2) return 48;
            if (v1 == 6) return 9;
        }
    }
    return (int64_t)(uint32_t)-9;
}

// ---- L0040 ----
int64_t L0040(int32_t a1)
{
    return ((((34 * a1) ^ 0x180) + 246) >> 3) ^ (((34 * a1) ^ 0x180u) + 246);
}

// ---- L0041 ----
int64_t L0041(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 31; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0042 ----
std::string L0042(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 19) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0043 ----
int64_t L0043(int32_t a1)
{
    if (a1 <= 0)
        return 5;
    if (a1 <= 6)
        return a1 * (uint32_t)L0043(a1 - 1) + 8;
    return L0043(a1 % 6);
}

// ---- L0044 ----
uint64_t L0044(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 5; ++i)
        v9.push_back((double)i * a1 - 0.51);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0045 ----
int64_t L0045(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x2745)) | 0xD1) - ((16 * a1 + (a1 ^ (uint32_t)0x2745)) >> 2);
}

// ---- L0046 ----
int64_t L0046(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 2 * a1 - a1 % 4);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (2 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0047 ----
int64_t L0047(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 6) return 39;
    if (v1 > 6) return (int64_t)(uint32_t)-5;
    if (v1 == 3) return 34;
    if (v1 > 3) return (int64_t)(uint32_t)-5;
    if (v1 == 1) return 30;
    if (v1 != 2) return (int64_t)(uint32_t)-5;
    return 25;
}

// ---- L0048 ----
int64_t L0048(int32_t a1)
{
    return ((((71 * a1) ^ 8) + 51) >> 3) ^ (((71 * a1) ^ 8u) + 51);
}

// ---- L0049 ----
int64_t L0049(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 11; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0050 ----
std::string L0050(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 22) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0051 ----
int64_t L0051(int32_t a1)
{
    if (a1 <= 0)
        return 4;
    if (a1 <= 7)
        return a1 * (uint32_t)L0051(a1 - 1) + 11;
    return L0051(a1 % 7);
}

// ---- L0052 ----
uint64_t L0052(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 4; ++i)
        v9.push_back((double)i * a1 - 0.294);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0053 ----
int64_t L0053(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x387D)) | 0x84) - ((16 * a1 + (a1 ^ (uint32_t)0x387D)) >> 2);
}

// ---- L0054 ----
int64_t L0054(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 2 * a1 - a1 % 7);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (2 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0055 ----
int64_t L0055(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 8) return 20;
    if (v1 > 8) return (int64_t)(uint32_t)-10;
    if (v1 == 6) return 33;
    if (v1 > 6) return (int64_t)(uint32_t)-10;
    if (v1 == 1) return 41;
    if (v1 != 2) return (int64_t)(uint32_t)-10;
    return 41;
}

// ---- L0056 ----
int64_t L0056(int32_t a1)
{
    return ((((26 * a1) ^ 0x50) + 154) >> 3) ^ (((26 * a1) ^ 0x50u) + 154);
}

// ---- L0057 ----
int64_t L0057(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 14; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0058 ----
std::string L0058(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 18) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0059 ----
int64_t L0059(int32_t a1)
{
    if (a1 <= 0)
        return 0;
    if (a1 <= 7)
        return a1 * (uint32_t)L0059(a1 - 1) + 20;
    return L0059(a1 % 7);
}

// ---- L0060 ----
uint64_t L0060(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 8; ++i)
        v9.push_back((double)i * a1 - 0.489);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0061 ----
int64_t L0061(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x2CA3)) | 0xFD) - ((16 * a1 + (a1 ^ (uint32_t)0x2CA3)) >> 2);
}

// ---- L0062 ----
int64_t L0062(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 7 * a1 - a1 % 7);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (7 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0063 ----
int64_t L0063(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 9) return 49;
    if (v1 > 9) return (int64_t)(uint32_t)-9;
    if (v1 == 3) return 32;
    if (v1 > 3) return (int64_t)(uint32_t)-9;
    if (v1 != 0) {
        if (v1 != 1) return (int64_t)(uint32_t)-9;
        return 5;
    }
    return 47;
}

// ---- L0064 ----
int64_t L0064(int32_t a1)
{
    return ((((99 * a1) ^ 0x44) - 328) >> 3) ^ (((99 * a1) ^ 0x44u) - 328);
}

// ---- L0065 ----
int64_t L0065(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 34; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0066 ----
std::string L0066(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 18) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0067 ----
int64_t L0067(int32_t a1)
{
    if (a1 <= 0)
        return 4;
    if (a1 <= 4)
        return a1 * (uint32_t)L0067(a1 - 1) + 17;
    return L0067(a1 % 4);
}

// ---- L0068 ----
uint64_t L0068(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 9; ++i)
        v9.push_back((double)i * a1 - 0.964);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0069 ----
int64_t L0069(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0xFDCD)) | 0x9A) - ((16 * a1 + (a1 ^ (uint32_t)0xFDCD)) >> 2);
}

// ---- L0070 ----
int64_t L0070(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 5 * a1 - a1 % 7);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (5 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0071 ----
int64_t L0071(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 8) return 5;
    if (v1 <= 8) {
        if (v1 == 7) return 15;
        if (v1 <= 7) {
            if (v1 == 0) return 22;
            if (v1 == 5) return 16;
        }
    }
    return (int64_t)(uint32_t)-1;
}

// ---- L0072 ----
int64_t L0072(int32_t a1)
{
    return ((((76 * a1) ^ 0x11C) - 92) >> 3) ^ (((76 * a1) ^ 0x11Cu) - 92);
}

// ---- L0073 ----
int64_t L0073(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 18; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0074 ----
std::string L0074(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 1) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0075 ----
int64_t L0075(int32_t a1)
{
    if (a1 <= 0)
        return 0;
    if (a1 <= 3)
        return a1 * (uint32_t)L0075(a1 - 1) + 8;
    return L0075(a1 % 3);
}

// ---- L0076 ----
uint64_t L0076(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 4; ++i)
        v9.push_back((double)i * a1 - 0.905);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0077 ----
int64_t L0077(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0xEC11)) | 0x64) - ((16 * a1 + (a1 ^ (uint32_t)0xEC11)) >> 2);
}

// ---- L0078 ----
int64_t L0078(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 3 * a1 - a1 % 11);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (3 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0079 ----
int64_t L0079(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 9) return 37;
    if (v1 <= 9) {
        if (v1 == 7) return 47;
        if (v1 <= 7) {
            if (v1 == 3) return 37;
            if (v1 == 4) return 9;
        }
    }
    return (int64_t)(uint32_t)-8;
}

// ---- L0080 ----
int64_t L0080(int32_t a1)
{
    return ((((32 * a1) ^ 0xF4) + 126) >> 3) ^ (((32 * a1) ^ 0xF4u) + 126);
}

// ---- L0081 ----
int64_t L0081(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 16; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0082 ----
std::string L0082(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 4) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0083 ----
int64_t L0083(int32_t a1)
{
    if (a1 <= 0)
        return 6;
    if (a1 <= 3)
        return a1 * (uint32_t)L0083(a1 - 1) + 12;
    return L0083(a1 % 3);
}

// ---- L0084 ----
uint64_t L0084(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 9; ++i)
        v9.push_back((double)i * a1 - 0.411);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0085 ----
int64_t L0085(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0xED24)) | 0xCA) - ((16 * a1 + (a1 ^ (uint32_t)0xED24)) >> 2);
}

// ---- L0086 ----
int64_t L0086(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 2 * a1 - a1 % 4);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (2 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0087 ----
int64_t L0087(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 7) return 29;
    if (v1 > 7) return (int64_t)(uint32_t)-3;
    if (v1 == 6) return 13;
    if (v1 > 6) return (int64_t)(uint32_t)-3;
    if (v1 == 1) return 35;
    if (v1 != 5) return (int64_t)(uint32_t)-3;
    return 13;
}

// ---- L0088 ----
int64_t L0088(int32_t a1)
{
    return ((((55 * a1) ^ 0x60) - 76) >> 3) ^ (((55 * a1) ^ 0x60u) - 76);
}

// ---- L0089 ----
int64_t L0089(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 33; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0090 ----
std::string L0090(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 8) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0091 ----
int64_t L0091(int32_t a1)
{
    if (a1 <= 0)
        return 7;
    if (a1 <= 3)
        return a1 * (uint32_t)L0091(a1 - 1) + 18;
    return L0091(a1 % 3);
}

// ---- L0092 ----
uint64_t L0092(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 4; ++i)
        v9.push_back((double)i * a1 - 0.051);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L0093 ----
int64_t L0093(int32_t a1)
{
    return ((16 * a1 + (a1 ^ 0x9A63)) | 0xE6) - ((16 * a1 + (a1 ^ (uint32_t)0x9A63)) >> 2);
}

// ---- L019837 (addr 0x68DE, between L0093 and L0094) -------------------
// L019837[abi:cxx11](): AES-256-CBC decrypt via OpenSSL EVP, matching
// EVP_DecryptInit_ex / EVP_DecryptUpdate / EVP_DecryptFinal_ex.
std::string L019837(const std::vector<unsigned char> &a2,
                     const unsigned char *key /* 32 bytes */,
                     const unsigned char *iv  /* 16 bytes */)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> plaintext(a2.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                           a2.data(), (int)a2.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (bad key/iv/padding)");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

// ---- L0094 ----
int64_t L0094(int32_t a1)
{
    // Original: LODWORD(v2) = a1 + M*a1 - a1%D; HIDWORD(v2) = (2*v2) ^ (M*a1);
    // Hex-Rays split-register artifact -- reconstructed with same ordering.
    int32_t lo = (int32_t)(a1 + 2 * a1 - a1 % 4);
    int64_t v2 = (uint32_t)lo;
    int32_t hi = (int32_t)((2 * v2) ^ (2 * a1));
    v2 = ((int64_t)hi << 32) | (uint32_t)lo;
    return v2;
}

// ---- L0095 ----
int64_t L0095(int32_t a1)
{
    int32_t v1 = a1 % 10;
    if (a1 % 10 == 7) return 4;
    if (v1 > 7) return (int64_t)(uint32_t)-7;
    if (v1 == 6) return 26;
    if (v1 > 6) return (int64_t)(uint32_t)-7;
    if (v1 == 2) return 14;
    if (v1 != 3) return (int64_t)(uint32_t)-7;
    return 11;
}

// ---- L0096 ----
int64_t L0096(int32_t a1)
{
    return (((a1 ^ 0xC8) + 66) >> 3) ^ ((a1 ^ 0xC8u) + 66);
}

// ---- L0097 ----
int64_t L0097(int64_t a1)
{
    int64_t v3 = 0;
    for (int32_t i = 0; i <= 33; ++i) {
        int64_t v4 = (i + a1) * (int64_t)(i % 3 - 1) + v3;
        v3 = (2 * v4) ^ v4;
    }
    return v3;
}

// ---- L0098 ----
std::string L0098(const std::string &a2)
{
    std::string a1;
    a1.reserve(a2.size());
    for (char c : a2)
        a1.push_back((char)((c + 10) % 128));
    std::reverse(a1.begin(), a1.end());
    return a1;
}

// ---- L0099 ----
int64_t L0099(int32_t a1)
{
    if (a1 <= 0)
        return 8;
    if (a1 <= 6)
        return a1 * (uint32_t)L0099(a1 - 1) + 16;
    return L0099(a1 % 6);
}

// ---- L0100 ----
uint64_t L0100(double a1)
{
    std::vector<double> v9;
    for (int32_t i = 0; i <= 5; ++i)
        v9.push_back((double)i * a1 - 0.19);

    double v6 = 0.0;
    for (double v8 : v9)
        v6 = v8 * v8 + v6;

    return (uint64_t)v6; // original returned a stack-canary artifact here
}

// ---- L333 (addr 0x711C, between L0100 and L_touch_all) -----------------
// L333(): hardcoded hex ciphertext + hardcoded key/IV blob, decrypt, print.
// Never called from main() -- exactly as in the original binary.
void L333()
{
    static const std::string hex_ciphertext =
        "643f86889af2fb7449c81831603cd956ebb205e45c9ef12938f9a93c89db93b5";

    // Original: qmemcpy(v22, "FIXED_IV_16BYTESNADI_SECRET_KEY_2026_32BYTES!!!!", 48);
    static const char key_iv_literal[] =
        "FIXED_IV_16BYTESNADI_SECRET_KEY_2026_32BYTES!!!!"; // 49 chars + NUL
    unsigned char key_iv_blob[48];
    std::memcpy(key_iv_blob, key_iv_literal, 48);

    const unsigned char *iv  = key_iv_blob;      // first 16 bytes
    const unsigned char *key = key_iv_blob + 16;  // next 32 bytes

    std::vector<unsigned char> ciphertext = djjsdjslksa(hex_ciphertext);
    std::string plaintext = L019837(ciphertext, key, iv);

    std::cout << plaintext << std::endl;
}

// ---- L_touch_all (addr 0x729A, right before main) ---------------------
// L_touch_all(): the only thing that ever calls into the decoys, and it
// is itself never called from main() -- true dead code.
int64_t L_touch_all()
{
    int64_t v2 = L0001(1);
    uint64_t v0 = L0004(3.0);
    return (int64_t)(int32_t)((double)v0 + (double)v2);
}

// ===========================================================================
// main() -- restored to match the ORIGINAL binary exactly.
// ===========================================================================
int main(int argc, const char **argv, const char **envp)
{
    std::cout << "What is NADI?" << std::endl;
    return 0;
}