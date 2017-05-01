#include "apdu.h"

APDU::APDU(byte aclass, byte ins, byte p1, byte p2, byte data_size, const byte* data) {
  _data = (byte*) malloc(5);

  if (_data == NULL) {
    printf("Can't allocate memory\n");
    exit(0);
  }

  set_class(aclass);
  set_ins(ins);
  set_p1(p1);
  set_p2(p2);
  set_data(data_size, data);
}

void APDU::set_data(byte size, const byte* data) {
  _data[OFFSET_LC] = 0;
  add_data(size, data);
}

void APDU::add_data(byte size, const byte* data) {
  if (_data == NULL) {
      return;
  }
  if (size == 0) {
    return;
  }

  byte* save_ptr = _data;
  _data = (byte*) realloc(_data, size + _data[OFFSET_LC] + 5);

  if (data == NULL) {
    free(save_ptr);
    printf("Can't allocate memory\n");
    exit(0);
  }

  for (int i = 0; i < size; i++) {
      _data[OFFSET_DATA + _data[OFFSET_LC] + i] = data[i];
  }
  _data[OFFSET_LC] = _data[OFFSET_LC] + size;
}

void APDU::add_data(CryptoPP::Integer data) {
  std::string dataString;

  for (int i = data.ByteCount() - 1; i >= 0; i--) {
    dataString.push_back(data.GetByte(i));
  }

  add_data(data.ByteCount(), (unsigned char*)dataString.c_str());
}

void APDU::add_data(CryptoPP::SecByteBlock data) {
  add_data(data.size(), (byte*) data.data());
}


APDU::~APDU() {
  if (_data != NULL) {
    free(_data);
  }
}
