#include "AES128GCM.h"

class TestFunctions
{
	static void testAES128GCM(byte* P, byte* A, byte* K, byte* IV, byte* C, byte* T, int lenP, int lenA);
public:
	static void test54BytePacketAES128GCM();
	static void test60BytePacketAES128GCM();
	static void test75BytePacketAES128GCM();
	static void testAllAES128GCM();
};

