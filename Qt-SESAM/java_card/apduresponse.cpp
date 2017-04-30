#include "apduresponse.h"

APDUResponse::APDUResponse() : _size(1024) {}

CryptoPP::Integer APDUResponse::asInteger() {
  return CryptoPP::Integer(_response, _size - 2);
}

CryptoPP::SecByteBlock APDUResponse::asSecByteBlock() {
  return CryptoPP::SecByteBlock((unsigned char*)_response, _size - 2);
}
