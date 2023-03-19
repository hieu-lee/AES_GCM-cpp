#include <iostream>
#include <chrono>
#include "AES128GCM.h"

void testPerformance() {
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
    std::cout << duration << std::endl;
    delete[] P;
}

int main()
{
    testPerformance();
}

