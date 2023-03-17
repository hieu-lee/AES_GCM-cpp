#include "TupleU128.h"

TupleU128::TupleU128(byte* _item1, byte* _item2)
{
	for (byte i = 0; i < 16; i++) {
		this->item1[i] = *_item1;
		this->item2[i] = *_item2;
		_item1++;
		_item2++;
	}
}
