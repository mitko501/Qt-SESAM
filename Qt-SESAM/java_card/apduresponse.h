#ifndef APDURESPONSE_H
#define APDURESPONSE_H

#include "PCSC/winscard.h"
#include "integer.h"

class APDUResponse {

private:
  byte _response[1024];
  DWORD _size;

public:
  APDUResponse();

  DWORD size() {
    return _size - 2;
  }

  DWORD* sizePtr() {
    return &_size;
  }

  byte* response() {
    return _response;
  }

  int isSuccessful() {
    return _response[_size - 2] == 0x90 && _response[_size - 1] == 0x00;
  }

  int getStatusCode() {
    int ret = _response[_size - 2];
    ret = (ret << 8) | _response[_size - 1];
    return ret;
  }

  CryptoPP::Integer asInteger();
  CryptoPP::SecByteBlock asSecByteBlock();
};

#endif // APDURESPONSE_H
