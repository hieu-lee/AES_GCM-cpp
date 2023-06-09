#include "GcmOutput.h"

GcmOutput::GcmOutput(byte* _cipherText, byte* _tag, int cipherLength)
{
	this->cipherText = _cipherText;
	this->cipherLength = cipherLength;
	for (byte i = 0; i < 16; i++) {
		this->tag[i] = _tag[i];
	}
}

GcmOutput::~GcmOutput()
{
	if (cipherLength) delete[] this->cipherText;
}
