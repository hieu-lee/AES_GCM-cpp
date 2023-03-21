#include <iostream>
#include <chrono>
#include "AES128GCM.h"
#include "TestFunctions.h"

long long testRun()
{
	byte K[16];
	byte IV[12];
	byte* P = new byte[1000000];
	byte A[24];
	int i;
	for (i = 0; i < 16; i++) {
		K[i] = (byte)rand();
	}
	for (i = 0; i < 12; i++) {
		IV[i] = (byte)rand();
	}
	for (i = 0; i < 1000000; i++) {
		P[i] = (byte)rand();
	}
	for (i = 0; i < 24; i++) {
		A[i] = (byte)rand();
	}
	auto start = std::chrono::high_resolution_clock::now();
	GcmOutput _ = AES128GCM::aes128gcmE(IV, P, A, K, 24, 1000000);
	long long duration = (std::chrono::high_resolution_clock::now() - start).count();
	delete[] P;
	return duration;
}

void testPerformance() 
{
	const int runs = 1500;
	long long averageTime = 0;
	for (int _ = 0; _ < runs; _++) {
		averageTime += testRun();
	}
	averageTime = averageTime / runs;
	std::cout << averageTime << "ns" << std::endl;
}

int main()
{
	testPerformance();
	return 0;
}

