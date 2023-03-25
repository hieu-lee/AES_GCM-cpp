#include "TupleU128.h"

typedef unsigned long long int ulong;
typedef unsigned int uint;

class AES128
{
	static const byte SBox[256];
	static const byte InvSBox[256];
	static const byte RCon[10];

private:
	static byte xTime(byte a);
	static void u128Copy(byte* src, byte* dst);
	static void invSubAndShiftRows(byte* state);
	static void mixColumns(byte* state);
	static void invMixColumns(byte* state);
	static void addRoundKey(byte* state, byte* roundKey);
	static void keyExpansion(byte* roundKey, int round);
	static void invKeyExpansion(byte* roundKey, int round);
	static void printArray(byte* arr, int length);

public:
	static void aes128EncryptPtr(byte* input, byte* key, byte* output);
	static TupleU128 aes128E(byte* input, byte* key);
	static TupleU128 aes128D(byte* cipherText, byte* key);
	static void test();
};

