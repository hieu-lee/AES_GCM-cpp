#include "AES128GCM.h"
#include <string>
#include <iostream>
using namespace std;

void AES128GCM::u128Copy(byte* src, byte* dst)
{
    ulong* srcLong = (ulong*)src;
    ulong* dstLong = (ulong*)dst;
    *dstLong = *srcLong;
    dstLong++;
    srcLong++;
    *dstLong = *srcLong;
}

void AES128GCM::inc32(byte* x)
{
    int lsb = 0;
    lsb |= x[12] << 24;
    lsb |= x[13] << 16;
    lsb |= x[14] << 8;
    lsb |= x[15];

    lsb++;

    int afterMod = lsb % twoP32;

    x[15] = (byte)afterMod;

    afterMod >>= 8;
    x[14] = (byte)afterMod;

    afterMod >>= 8;
    x[13] = (byte)afterMod;

    afterMod >>= 8;
    x[12] = (byte)afterMod;
}

void AES128GCM::rightShift(byte* v)
{
    byte i;
    byte lowestBit, highestBit;
    lowestBit = *v & 1;
    *v >>= 1;
    v++;
    highestBit = lowestBit;
    for (i = 1; i < 16; i++)
    {
        lowestBit = *v & 1;
        *v >>= 1;
        if (highestBit == 1)
        {
            *v |= 0x80;
        }
        v++;
        highestBit = lowestBit;
    }
}

void AES128GCM::xorBlock128(byte* dst, byte* src)
{
    ulong* dstLong = (ulong*)dst;
    ulong* srcLong = (ulong*)src;
    *dstLong ^= *srcLong;
    dstLong++;
    srcLong++;
    *dstLong ^= *srcLong;
}

void AES128GCM::concateBlock(ulong lengthA, ulong lengthB, byte* output)
{
    ulong* pOutput = (ulong*)output;
    *pOutput = (lengthA << 3);
    pOutput++;
    *pOutput = (lengthB << 3);
    for (byte i = 0; i < 4; i++)
    {
        byte a = 7 - i, b = 8 + i, c = 15 - i;
        (output[i], output[a]) = (output[a], output[i]);
        (output[b], output[c]) = (output[c], output[b]);
    }
}

void AES128GCM::gMult(byte* X, byte* Y, byte* output)
{

    byte V[16];

    int i, j, lsb;

    byte Z[16];

    u128Copy(Y, V);

    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (((*X >> (7 - j)) & 1) == 1)
            {
                xorBlock128(Z, V);
            }
            lsb = V[15] & 0x01;
            rightShift(V);

            if (lsb == 1)
            {
                *V ^= 0xe1;
            }

        }
        X++;
    }

    u128Copy(Z, output);
}

void AES128GCM::gHash(byte* H, byte* X, int lenX, byte* output)
{
    int c;
    byte temp[16];
    u128Copy(X, temp);
    byte Y[16];

    gMult(H, temp, Y);
    for (int i = 1; i < lenX; i++)
    {
        c = i << 4;
        for (int j = 0; j < 16; j++)
        {
            temp[j] = X[c + j];
        }
        xorBlock128(Y, temp);
        gMult(Y, H, Y);
    }

    u128Copy(Y, output);
}

void AES128GCM::gCtr128(byte* K, byte* ICB, byte* X, byte* tag)
{
    byte tmp[16];
    byte CB[16];
    u128Copy(ICB, CB);

    AES128::aes128EncryptPtr(CB, K, tmp);
    *(ulong*)tag = *(ulong*)tmp ^ *(ulong*)X;
    *(ulong*)(tag + 8) = *(ulong*)(tmp + 8) ^ *(ulong*)(X + 8);
}

void AES128GCM::gCtr(byte* K, byte* ICB, byte* X, int lenX, int lastLenX, byte* cipher)
{
    byte CB[16];
    if (lenX == 0)
    {
        return;
    }
    int i, j, c;
    byte tmp[16];
    u128Copy(ICB, CB);

    for (i = 0; i < lenX - 1; i++)
    {
        c = i << 4;
        AES128::aes128EncryptPtr(CB, K, tmp);
        for (j = 0; j < 16; j++)
        {
            cipher[c + j] = tmp[j] ^ X[c + j];
        }
        inc32(CB);
    }

    AES128::aes128EncryptPtr(CB, K, tmp);
    c = (lenX - 1) << 4;
    for (i = 0; i < lastLenX; i++)
    {
        cipher[c + i] = (byte)(tmp[i] ^ X[c + i]);
    }
}

void AES128GCM::printArray(byte* arr, int length)
{
    string s = "[";
    for (int i = 0; i < length; i++) {
        s.append(to_string(arr[i]) + ", ");
    }
    s.append("]\n");
    cout << s;
}

GcmOutput AES128GCM::aes128gcmE(byte* IV, byte* _P, byte* _A, byte* K, int lenA, int lenP)
{
    byte key[16];
    int last_len_a = ((lenA & 15) == 0) ? 16 : (lenA & 15);
    int last_len_p = ((lenP & 15) == 0) ? 16 : (lenP & 15);
    int len_a = (last_len_a == 16) ? (lenA >> 4) : ((lenA >> 4) + 1);
    int len_p = (last_len_p == 16) ? (lenP >> 4) : ((lenP >> 4) + 1);
    byte* C = new byte[lenP];
    byte T[16];
    byte H[16];
    byte ZeroU128[16];
    *(ulong*)ZeroU128 = 0;
    *(ulong*)(ZeroU128 + 8) = 0;
    u128Copy(K, key);
    AES128::aes128EncryptPtr(ZeroU128, key, H);
    byte Y0[16];
    *(uint*)(Y0 + 12) = 16777216;
    byte* scan = IV;
    *(ulong*)Y0 = *(ulong*)scan;
    scan += 8;
    *(uint*)(Y0 + 8) = *(uint*)scan;
    inc32(Y0);
    gCtr(key, Y0, _P, len_p, last_len_p, C);
    byte temp[16];
    concateBlock((ulong)lenA, (ulong)lenP, temp);
    len_a <<= 4;
    len_p <<= 4;
    int l = len_a + len_p + 16;
    byte* tmp = new byte[l];
    for (int i = 0; i < lenA; i++)
    {
        tmp[i] = _A[i];
    }
    for (int i = len_a; i < len_a + lenP; i++)
    {
        tmp[i] = C[i - len_a];
    }
    int c = l - 16;
    for (int i = c; i < l; i++)
    {
        tmp[i] = temp[i - c];
    }
    byte S[16];
    gHash(H, tmp, l >> 4, S);
    *(uint*)(Y0 + 12) = 16777216;
    scan = IV;
    *(ulong*)Y0 = *(ulong*)scan;
    scan += 8;
    *(uint*)(Y0 + 8) = *(uint*)scan;
    gCtr128(key, Y0, S, T);
    return GcmOutput(C, T);
}

byte* AES128GCM::aes128gcmD(byte* IV, byte* _C, byte* K, byte* _A, byte* _T, int lenA, int lenC)
{
    byte key[16];
    int last_len_a = ((lenA & 15) == 0) ? 16 : (lenA & 15);
    int last_len_c = ((lenC & 15) == 0) ? 16 : (lenC & 15);
    int len_a = (last_len_a == 16) ? (lenA >> 4) : ((lenA >> 4) + 1);
    int len_c = (last_len_c == 16) ? (lenC >> 4) : ((lenC >> 4) + 1);
    byte* P = new byte[lenC];
    byte T[16];
    byte H[16];
    byte ZeroU128[16];
    *(ulong*)ZeroU128 = 0;
    *(ulong*)(ZeroU128 + 8) = 0;
    u128Copy(K, key);
    AES128::aes128EncryptPtr(ZeroU128, key, H);
    byte Y0[16];
    *(uint*)(Y0 + 12) = 16777216;
    byte* scan = IV;
    *(ulong*)Y0 = *(ulong*)scan;
    scan += 8;
    *(uint*)(Y0 + 8) = *(uint*)scan;
    inc32(Y0);

    gCtr(key, Y0, _C, len_c, last_len_c, P);

    byte temp[16];
    concateBlock((ulong)lenA, (ulong)lenC, temp);
    len_a <<= 4;
    len_c <<= 4;
    int l = len_a + len_c + 16;
    byte* tmp = new byte[l];
    for (int i = 0; i < lenA; i++)
    {
        tmp[i] = _A[i];
    }
    for (int i = len_a; i < len_a + lenC; i++)
    {
        tmp[i] = _C[i - len_a];
    }
    int c = l - 16;
    for (int i = c; i < l; i++)
    {
        tmp[i] = temp[i - c];
    }
    byte S[16];
    gHash(H, tmp, l >> 4, S);
    *(uint*)(Y0 + 12) = 16777216;
    scan = IV;
    *(ulong*)Y0 = *(ulong*)scan;
    scan += 8;
    *(uint*)(Y0 + 8) = *(uint*)scan;
    gCtr128(key, Y0, S, T);
    scan = _T;
    if ((*(ulong*)T != *(ulong*)scan) || (*(ulong*)(T + 8) != *(ulong*)(scan + 8)))
    {
        cout << "FAIL" << endl;
        return { 0 };
    }
    return P;
}

void AES128GCM::test()
{
    byte K[16] = {
        0x98,0xff,0xf6,0x7e,0x64,0xe4,0x6b,0xe5,0xee,0x2e,0x05,0xcc,0x9a,0xf6,0xd0,0x12
    };

    byte IV[12] = {
        0x2d, 0xfb, 0x42, 0x9a, 0x48, 0x69, 0x7c, 0x34, 0x00, 0x6d, 0xa8, 0x86
    };

    byte P[48] = {
        0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a,
        0x7a,0xfc,0x9e,0x1a,0xca,0x83,0xe1,0x29,0xb0,0x85,0xbd,0x63,0x7f,0xf6,0x7c,0x01,
        0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a
    };

    byte A[48] = {
        0xa0,0xca,0x58,0x61,0xc0,0x22,0x6c,0x5b,0x5a,0x65,0x14,0xc8,0x2b,0x77,0x81,0x5a,
        0x9e,0x0e,0xb3,0x59,0xd0,0xd4,0x6d,0x03,0x33,0xc3,0xf2,0xba,0xe1,0x4d,0xa0,0xc4,
        0x03,0x30,0xc0,0x02,0x16,0xb4,0xaa,0x64,0xb7,0xc1,0xed,0xb8,0x71,0xc3,0x28,0xf6
    };

    byte ciphertextRef[48] = {
        0xc2,0x2f,0xee,0xb3,0xe2,0x7d,0xc3,0x29,0x93,0x45,0x03,0x01,0x39,0xee,0x81,0x67,
        0x19,0xa8,0xa8,0x99,0x39,0x03,0x78,0x95,0xd7,0x49,0x65,0xfa,0x02,0x40,0xaf,0x5b,
        0xe3,0x19,0x26,0x59,0xd5,0x66,0x39,0x8a,0x5d,0x95,0xf3,0xe0,0x4b,0xcd,0x53,0x57
    };

    GcmOutput resE = aes128gcmE(IV, P, A, K, 48, 48);

    byte* C = resE.cipherText;
    byte* T = resE.tag;

    byte* resD = aes128gcmD(IV, C, K, A, T, 48, 48);

    cout << "Ciphertext result:" << endl;
    printArray(C, 48);

    cout << "\nCiphertext reference:" << endl;
    printArray(ciphertextRef, 48);

    cout << "\nPlaintext reference:" << endl;
    printArray(P, 48);

    cout << "\nPlaintext result:" << endl;
    printArray(resD, 48);
}
