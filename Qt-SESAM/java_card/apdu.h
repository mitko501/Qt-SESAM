#ifndef APDU_H
#define APDU_H

#include <stdio.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include "integer.h"

#include "PCSC/winscard.h"

class APDU {

private:
  const byte HEADER_SIZE = 5;
  const byte OFFSET_CLA = 0;
  const byte OFFSET_INS = 1;
  const byte OFFSET_P1 = 2;
  const byte OFFSET_P2 = 3;
  const byte OFFSET_LC = 4;
  const byte OFFSET_DATA = 5;
  byte* _data = NULL;

public:
  /**
   * @brief APDU Create clean APDU with applet class
   */
  APDU() : APDU(0xB0, 0x00, 0x00, 0x00, 0x00, NULL) {}

  /**
   * @brief APDU Create APDU with class and data
   * @param data_size
   * @param data
   */
  APDU(byte data_size, const byte* data) : APDU(0xB0, 0x00, 0x00, 0x00, data_size, data) {} // Create APDU with data

  APDU(byte ins) : APDU(0xB0, ins, 0x00, 0x00, 0x00, NULL) {}

  APDU(byte aclass, byte ins, byte p1, byte p2, byte data_size, const byte* data);

  void set_class(byte aclass) {
    _data[OFFSET_CLA] = aclass;
  }

  byte get_class() {
    return _data[OFFSET_CLA];
  }

  void set_ins(byte ins) {
    _data[OFFSET_INS] = ins;
  }

  byte get_ins() {
    return _data[OFFSET_INS];
  }

  void set_p1(byte p1) {
    _data[OFFSET_P1] = p1;
  }

  byte get_p1() {
    return _data[OFFSET_P1];
  }

  void set_p2(byte p2) {
    _data[OFFSET_P2]= p2;
  }

  byte get_p2() {
    return _data[OFFSET_P2];
  }

  byte* getDataPtr() {
    return _data + OFFSET_DATA;
  }

  void set_data(byte size, const byte* data);

  void add_data(byte size, const byte* data);

  void add_data(const CryptoPP::Integer data);

  void add_data(const CryptoPP::SecByteBlock data);

  byte size() const {
    return _data[OFFSET_LC] + HEADER_SIZE;
  }

  byte dataSize() const {
    return _data[OFFSET_LC];
  }

  byte* getRawAPDU() const {
    return _data;
  }

  ~APDU();
};

#endif // APDU_H
