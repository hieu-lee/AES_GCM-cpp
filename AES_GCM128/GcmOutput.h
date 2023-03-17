#pragma once

#define byte unsigned char

struct GcmOutput
{
	byte* cipherText;
	byte* tag;

public:
	GcmOutput(byte* _cipherText, byte* _tag);
};

