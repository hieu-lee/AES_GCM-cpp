#pragma once

#define byte unsigned char

struct TupleU128
{
	byte item1[16];
	byte item2[16];

public:
	TupleU128(byte* _item1, byte* _item2);
};

