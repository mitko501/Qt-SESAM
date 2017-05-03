#ifndef APDURESPONSE_H
#define APDURESPONSE_H

#include "integer.h"

#ifdef _WIN32
  #include <winscard.h>
#else
  #include "PCSC/winscard.h"
#endif

class APDUResponse {

private:
  byte _response[1024]; //< Response buffer
  DWORD _size; //< Actual size of the resposne

public:
  APDUResponse(); //< Sets the _size to 1024
  /**
   * @brief size
   * @return size of the response without response code
   */
  DWORD size() {
    return _size - 2;
  }
  /**
   * @brief sizePtr
   * @return reference to size
   */
  DWORD* sizePtr() {
    return &_size;
  }
  /**
   * @brief response
   * @return response buffer
   */
  byte* response() {
    return _response;
  }
  /**
   * @brief isSuccessful
   * @return true if reponse contains return code 0x9000, false otherwise
   */
  int isSuccessful() {
    return _response[_size - 2] == 0x90 && _response[_size - 1] == 0x00;
  }
  /**
   * @brief getStatusCode
   * @return status code of last response message
   */
  int getStatusCode() {
    int ret = _response[_size - 2];
    ret = (ret << 8) | _response[_size - 1];
    return ret;
  }
  /**
   * @brief asInteger convert byte array to crypto to integer
   * @return response buffer as interger
   */
  CryptoPP::Integer asInteger();
  /**
   * @brief asSecByteBlock convert byte array to secure memory block
   * @return response buffer as secure memory block
   */
  CryptoPP::SecByteBlock asSecByteBlock();
};

#endif // APDURESPONSE_H
