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
  APDU(): APDU(0xB0, 0x00, 0x00, 0x00, 0x00, NULL) {}
  /**
   * @brief APDU Create APDU with class and data
   * @param data_size
   * @param data
   */
  APDU(byte data_size, const byte* data):
      APDU(0xB0, 0x00, 0x00, 0x00, data_size, data) {}
  /**
   * @brief APDU
   * @param ins instruction to perform on applet
   */
  APDU(byte ins) : APDU(0xB0, ins, 0x00, 0x00, 0x00, NULL) {}
  /**
   * @brief APDU sets data w.r.t. to parameters
   * @param aclass instruction class
   * @param ins instruction code
   * @param p1 instruction paramater
   * @param p2 instruction parameter
   * @param data_size size of the data
   * @param data data
   */
  APDU(byte aclass, byte ins, byte p1, byte p2, byte data_size, const byte* data);
  /**
   * @brief set_class set class of APDU command
   * @param aclass class to set
   */
  void set_class(byte aclass) {
    _data[OFFSET_CLA] = aclass;
  }
  /**
   * @brief get_class
   * @return code of class
   */
  byte get_class() {
    return _data[OFFSET_CLA];
  }
  /**
   * @brief set_ins set instruction of APDU command
   * @param ins instruction to set
   */
  void set_ins(byte ins) {
    _data[OFFSET_INS] = ins;
  }
  /**
   * @brief get_ins get code of instruction
   * @return code of instruction
   */
  byte get_ins() {
    return _data[OFFSET_INS];
  }
  /**
   * @brief set_p1 sets instruction parameter 1
   * @param p1 parameter 1
   */
  void set_p1(byte p1) {
    _data[OFFSET_P1] = p1;
  }
  /**
   * @brief get_p1 get instruction parameter 1
   * @return instruction parameter 1
   */
  byte get_p1() {
    return _data[OFFSET_P1];
  }
  /**
   * @brief set_p2 set instruction parameter 2
   * @param p2 parameter 2
   */
  void set_p2(byte p2) {
    _data[OFFSET_P2]= p2;
  }
  /**
   * @brief get_p2 get instruction parameter 2
   * @return instruction parameter 2
   */
  byte get_p2() {
    return _data[OFFSET_P2];
  }
  /**
   * @brief getDataPtr get pointer on start of data section
   * @return pointer on start of data section
   */
  byte* getDataPtr() {
    return _data + OFFSET_DATA;
  }
  /**
   * @brief set_data set data from byte buffer and forget about previous one
   * @param size size of the data
   * @param data
   */
  void set_data(byte size, const byte* data);
  /**
   * @brief add_data append data to previous one
   * @param size
   * @param data
   */
  void add_data(byte size, const byte* data);
  /**
   * @brief add_data append data from crypto integer
   * @param data data to append
   */
  void add_data(const CryptoPP::Integer data);
  /**
   * @brief add_data append data from byte block
   * @param data data to append
   */
  void add_data(const CryptoPP::SecByteBlock data);
  /**
   * @brief size
   * @return size of data buffer plus header size
   */
  byte size() const {
    return _data[OFFSET_LC] + HEADER_SIZE;
  }
  /**
   * @brief dataSize
   * @return size of the data block
   */
  byte dataSize() const {
    return _data[OFFSET_LC];
  }
  /**
   * @brief getRawAPDU
   * @return raw data bytes
   */
  byte* getRawAPDU() const {
    return _data;
  }
  /**
   * @brief APDU remove byte data block and free up the memory
   */
  ~APDU();
};

#endif // APDU_H
