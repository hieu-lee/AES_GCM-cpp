#include "AES128GCM.h"
#include <string>
#include <iostream>
#include <emmintrin.h>
using namespace std;

void AES128GCM::u128Copy(byte* src, byte* dst)
{
	_mm_storeu_si128((__m128i*)dst, _mm_loadu_si128((__m128i*)src));
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
	ulong temp;
	ulong* vLong = (ulong*)v;
	temp = getLastBits & *vLong;
	temp <<= 15;
	byte highestBit = v[7] & 1;
	*vLong >>= 1;
	*vLong &= setFirstBits;
	*vLong |= temp;

	vLong++;

	temp = getLastBits & *vLong;
	temp <<= 15;
	*vLong >>= 1;
	*vLong &= setFirstBits;
	*vLong |= temp;
	v = (byte*)vLong;
	if (highestBit) v[0] |= 0x80;
}

void AES128GCM::xorBlock128(byte* dst, byte* src)
{
	__m128i result = _mm_xor_si128(_mm_loadu_si128((__m128i*)dst), _mm_loadu_si128((__m128i*)src));
	_mm_storeu_si128((__m128i*)dst, result);
}

void AES128GCM::concateBlock(ulong lengthA, ulong lengthB, byte* output)
{
	ulong* pOutput = (ulong*)output;
	*pOutput = (lengthA << 3);
	pOutput++;
	*pOutput = (lengthB << 3);
	byte i, a, b, c, tmp;
	for (i = 0; i < 4; i++)
	{
		a = 7 - i;
		b = 8 + i;
		c = 15 - i;
		tmp = output[a];
		output[a] = output[i];
		output[i] = tmp;
		tmp = output[c];
		output[c] = output[b];
		output[b] = tmp;
	}
}

void AES128GCM::gMult(byte* X, byte* Y, byte* output)
{

	byte V[16];

	byte i, j, lsb;

	byte Z[16] = { 0 };

	u128Copy(Y, V);

	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < 8; j++)
		{
			if (((*X >> (7 - j)) & 1))
			{
				xorBlock128(Z, V);
			}
			lsb = V[15] & 0x01;
			rightShift(V);

			if (lsb)
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
	byte temp[16];
	u128Copy(X, temp);
	byte Y[16];
	int i;

	gMult(H, temp, Y);
	for (i = 1; i < lenX; i++)
	{
		X += 16;
		xorBlock128(Y, X);
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
	if (!lenX)
	{
		return;
	}
	int i, c;
	byte tmp[16];
	ulong* cipherLong;
	ulong* XLong;
	ulong* tmpLong;
	u128Copy(ICB, CB);

	for (i = 0; i < lenX - 1; i++)
	{
		c = i << 4;
		AES128::aes128EncryptPtr(CB, K, tmp);
		cipherLong = (ulong*)(cipher + c);
		XLong = (ulong*)(X + c);
		tmpLong = (ulong*)tmp;
		*cipherLong = *tmpLong ^ *XLong;
		cipherLong++;
		tmpLong++;
		XLong++;
		*cipherLong = *tmpLong ^ *XLong;
		inc32(CB);
	}

	AES128::aes128EncryptPtr(CB, K, tmp);
	c = (lenX - 1) << 4;
	for (i = 0; i < lastLenX; i++)
	{
		cipher[c + i] = tmp[i] ^ X[c + i];
	}
}

void AES128GCM::printArray(byte* arr, int length)
{
	string s = "[";
	for (int i = 0; i < length; i++) 
	{
		s.append(to_string(arr[i]) + ", ");
	}
	s.append("]\n");
	cout << s;
}

GcmOutput AES128GCM::aes128gcmE(byte* IV, byte* _P, byte* _A, byte* K, int lenA, int lenP)
{
	byte key[16];
	int i;
	int last_len_a = ((lenA & 15) == 0) ? 16 : (lenA & 15);
	int last_len_p = ((lenP & 15) == 0) ? 16 : (lenP & 15);
	int len_a = (last_len_a == 16) ? (lenA >> 4) : ((lenA >> 4) + 1);
	int len_p = (last_len_p == 16) ? (lenP >> 4) : ((lenP >> 4) + 1);
	byte* C = new byte[lenP]{ 0 };
	byte T[16];
	byte H[16];
	byte ZeroU128[16]{ 0 };
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
	byte* tmp = new byte[l]{ 0 };
	for (i = 0; i < lenA; i++)
	{
		tmp[i] = _A[i];
	}
	for (i = len_a; i < len_a + lenP; i++)
	{
		tmp[i] = C[i - len_a];
	}
	u128Copy(temp, tmp + l - 16);
	byte S[16];
	gHash(H, tmp, l >> 4, S);
	delete[] tmp;
	*(uint*)(Y0 + 12) = 16777216;
	scan = IV;
	*(ulong*)Y0 = *(ulong*)scan;
	scan += 8;
	*(uint*)(Y0 + 8) = *(uint*)scan;
	gCtr128(key, Y0, S, T);
	return GcmOutput(C, T, lenP);
}

byte* AES128GCM::aes128gcmD(byte* IV, byte* _C, byte* K, byte* _A, byte* _T, int lenA, int lenC)
{
	byte key[16];
	int i;
	int last_len_a = ((lenA & 15) == 0) ? 16 : (lenA & 15);
	int last_len_c = ((lenC & 15) == 0) ? 16 : (lenC & 15);
	int len_a = (last_len_a == 16) ? (lenA >> 4) : ((lenA >> 4) + 1);
	int len_c = (last_len_c == 16) ? (lenC >> 4) : ((lenC >> 4) + 1);
	byte* P = new byte[lenC];
	byte T[16];
	byte H[16];
	byte ZeroU128[16] = { 0 };
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
	for (i = 0; i < lenA; i++)
	{
		tmp[i] = _A[i];
	}
	for (i = len_a; i < len_a + lenC; i++)
	{
		tmp[i] = _C[i - len_a];
	}
	u128Copy(temp, tmp + l - 16);
	byte S[16];
	gHash(H, tmp, l >> 4, S);
	delete[] tmp;
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
		for (i = 0; i < lenC; i++) {
			P[i] = 0;
		}
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

	byte* resD = aes128gcmD(IV, C, K, A, resE.tag, 48, 48);

	cout << "Ciphertext result:" << endl;
	printArray(C, 48);

	cout << "\nCiphertext reference:" << endl;
	printArray(ciphertextRef, 48);

	cout << "\nPlaintext reference:" << endl;
	printArray(P, 48);

	cout << "\nPlaintext result:" << endl;
	printArray(resD, 48);

	delete[] resD;
}

void AES128GCM::testTag()
{
	byte P[60] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39 };
	byte K[16] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
	byte IV[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
	byte A[20] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };
	byte tag[16] = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47 };
	byte C[60] = { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91 };

	GcmOutput res = aes128gcmE(IV, P, A, K, 20, 60);

	for (int i = 0; i < 60; i++) {
		if (C[i] != res.cipherText[i]) {
			cout << "FAIL CIPHER" << endl;
			return;
		}
	}

	for (int i = 0; i < 16; i++) {
		if (tag[i] != res.tag[i]) {
			cout << "FAIL TAG" << endl;
			return;
		}
	}

	cout << "OK" << endl;
}
