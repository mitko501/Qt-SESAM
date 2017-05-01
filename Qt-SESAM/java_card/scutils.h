#ifndef SCUTILS_H
#define SCUTILS_H

#include <vector>
#include "PCSC/winscard.h"
#include "apdu.h"
#include "apduresponse.h"
#include "rsa.h"
#include "osrng.h"

#define NUMBER_OF_TRIES 50

class SCUtils
{

private:

  std::vector<std::string> _readers;
  SCARDCONTEXT _context;
  SCARDHANDLE  _card;
  DWORD _protocol;

  CryptoPP::Integer _cardPublicKey;
  CryptoPP::Integer _cardModulus;

  const byte AID[12] = {0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x74};
  APDU* SELECT_APPLET_APDU = NULL;

  void selectApplet();

  const SCARD_IO_REQUEST determineProtocolStructure();

public:
  SCUtils();

  LONG sendToCard(const APDU* apdu, APDUResponse* response);
  
  void connectToCardAndSetQtSESAMApplet();
  void readCardPublicKey();
  void sendAPDUEncryptedByCardPKI(APDU* apdu, APDUResponse* response);

  ~SCUtils();
};

#endif // SCUTILS_H
