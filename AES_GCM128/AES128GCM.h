#pragma once

#include "AES128.h"
#include "GcmOutput.h"

class AES128GCM
{
	static const int twoP32 = 4294967;

private:
	static void u128Copy(byte* src, byte* dst);
	static void inc32(byte* x);
	static void rightShift(byte* v);
	static void xorBlock128(byte* dst, byte* src);
	static void concateBlock(ulong lengthA, ulong lengthB, byte* output);
	static void gMult(byte* X, byte* Y, byte* output);
	static void gHash(byte* H, byte* X, int lenX, byte* output);
	static void gCtr128(byte* K, byte* ICB, byte* X, byte* tag);
	static void gCtr(byte* K, byte* ICB, byte* X, int lenX, int lastLenX, byte* cipher);
	static void printArray(byte* arr, int length);

public:
	static GcmOutput aes128gcmE(byte* IV, byte* _P, byte* _A, byte* K, int lenA, int lenP);
	static byte* aes128gcmD(byte* IV, byte* _C, byte* K, byte* _A, byte* _T, int lenA, int lenC);
	static void test();
};
