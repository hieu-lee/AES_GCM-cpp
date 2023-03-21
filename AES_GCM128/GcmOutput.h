typedef unsigned char byte;

struct GcmOutput
{
	byte* cipherText;
	byte tag[16];

private:
	int cipherLength;

public:
	GcmOutput(byte* _cipherText, byte* _tag, int _cipherLength);
	~GcmOutput();
};

