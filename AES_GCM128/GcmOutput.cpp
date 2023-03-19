#include "GcmOutput.h"

GcmOutput::GcmOutput(byte* _cipherText, byte* _tag)
{
	this->cipherText = _cipherText;
	for (byte i = 0; i < 16; i++) {
		this->tag[i] = _tag[i];
	}
}

GcmOutput::~GcmOutput()
{
	delete[] this->cipherText;
}
