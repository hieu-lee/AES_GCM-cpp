#pragma once

#define byte unsigned char

struct GcmOutput
{
	byte* cipherText;
	byte tag[16];

public:
	GcmOutput(byte* _cipherText, byte* _tag);
	~GcmOutput();
};

