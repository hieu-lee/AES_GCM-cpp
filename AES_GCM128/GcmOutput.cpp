#include "GcmOutput.h"

GcmOutput::GcmOutput(byte* _cipherText, byte* _tag)
{
	this->cipherText = _cipherText;
	this->tag = _tag;
}
