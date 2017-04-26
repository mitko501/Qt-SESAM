#ifndef SCUTILS_H
#define SCUTILS_H

#include <iostream>
#include <vector>
#include "PCSC/winscard.h"
#define NUMBER_OF_TRIES 50

class SCManager
{

private:
  std::vector<std::string> _readers;
  SCARDCONTEXT _context;
  SCARDHANDLE  _card;
  DWORD _protocol;

  unsigned char AID[10] = {0x4C, 0x61, 0x62, 0x6B, 0x41, 0x70, 0x70, 0x6C, 0x65, 0x74};

public:
  SCManager();

  void connectToCardAndSetQtSESAMApplet();
};

#endif // SCUTILS_H
