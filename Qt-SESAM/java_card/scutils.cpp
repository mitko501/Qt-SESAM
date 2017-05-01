#include "scutils.h"

SCUtils::SCUtils() {
  LONG rval;
  rval = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &_context);

  if (rval != SCARD_S_SUCCESS) {
    printf("Fail during establishing context\n");
    exit(0); // TODO: throw exception
  }

  LPTSTR pmszReaders = NULL;
  LPTSTR pReader;
  DWORD cch = SCARD_AUTOALLOCATE;

  // Retrieve the list the readers.
  // hSC was set by a previous call to SCardEstablishContext.
  rval = SCardListReaders(_context, NULL, (LPTSTR)&pmszReaders, &cch );

  if (rval != SCARD_S_SUCCESS) {
    printf("Fail during listing reading\n");
    exit(0); // TODO: throw exception
  }

  pReader = pmszReaders;
  while ( '\0' != *pReader ) {
    std::string reader_name(pReader);
    _readers.push_back(reader_name);
    
    pReader = pReader + reader_name.size() + 1;
  }

  // Free the memory pmszReaders.
  rval = SCardFreeMemory( _context, pmszReaders);
  if ( SCARD_S_SUCCESS != rval )
    printf("Failed to free memory\n");
}

const SCARD_IO_REQUEST SCUtils::determineProtocolStructure() {
  switch(_protocol) {
    case SCARD_PROTOCOL_T0:
      return *SCARD_PCI_T0;
    case SCARD_PROTOCOL_T1:
      return *SCARD_PCI_T1;
    default:
      printf("Can't determine protocol structure\n");
      exit(0);
  }
}

LONG SCUtils::sendToCard(const APDU* apdu, APDUResponse* response) {
  SCARD_IO_REQUEST protocolStructure = determineProtocolStructure();

  return SCardTransmit(_card, &protocolStructure, apdu->getRawAPDU(), apdu->size(), NULL, response->response(), response->sizePtr());
}

void SCUtils::connectToCardAndSetQtSESAMApplet() {
  LONG rval;

  // Loop over all readers and find card connected
  for (auto reader : _readers) {
    int tries = NUMBER_OF_TRIES;
    while (tries && (rval = SCardConnect(_context, (LPCTSTR)_readers.at(0).c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &_card, &_protocol)) != SCARD_S_SUCCESS) {
        tries--;
    }

    if (rval == SCARD_S_SUCCESS)
      // CARD FOUND
      break;
    tries = NUMBER_OF_TRIES;
  }

  if (rval != SCARD_S_SUCCESS) {
    printf("Connection to card was unsuccessful.\n");
    exit(0); // TODO throw exception
  }

  APDUResponse response;
  SELECT_APPLET_APDU = new APDU(0x00, 0xa4, 0x04, 0x00, 0x0c, AID);
  rval = sendToCard(SELECT_APPLET_APDU, &response);

  if (rval != SCARD_S_SUCCESS || !response.isSuccessful()) {
    printf("Unable to set Qt-sesam applet\n");
    exit(0);
  }
}

void SCUtils::readCardPublicKey() {
  APDU getPK(0x70);
  APDUResponse response;

  sendToCard(&getPK, &response);
  if(!response.isSuccessful()) {
    printf("Unable to get Public Key of card\n");
    exit(0);
  }

  _cardPublicKey = response.asInteger();

  APDUResponse response2;

  APDU getModulus(0x71);

  sendToCard(&getModulus, &response2);
  if(!response2.isSuccessful()) {
    printf("Unable to get Modulus of card\n");
    exit(0);
  }

  _cardModulus = response2.asInteger();
}

void SCUtils::sendAPDUEncryptedByCardPKI(APDU* apdu, APDUResponse* response) {
  CryptoPP::AutoSeededRandomPool rng;
  APDU encryptedAPDU(apdu->get_class(), apdu->get_ins(), apdu->get_p1(), apdu->get_p2(),
                     0x00, NULL);

  CryptoPP::RSA::PublicKey pubKey;
  pubKey.Initialize(_cardModulus, _cardPublicKey);

  CryptoPP::RSAES_PKCS1v15_Encryptor enc(pubKey);
  byte ciphert[160];
  enc.Encrypt(rng, (unsigned char*) apdu->getDataPtr(), apdu->dataSize(), ciphert);

  encryptedAPDU.add_data(160, ciphert);

  sendToCard(&encryptedAPDU, response);
}

SCUtils::~SCUtils() {
  if (SELECT_APPLET_APDU != NULL) {
    delete SELECT_APPLET_APDU;
  }
}


