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

  std::vector<std::string> _readers; //< Vector of connected readers
  SCARDCONTEXT _context; //< Returned application context
  SCARDHANDLE  _card; //< Connected card
  DWORD _protocol; //< Established protocol to this connection

  CryptoPP::Integer _cardPublicKey; //< Public key obtained from the card
  CryptoPP::Integer _cardModulus; //< Modulus obtained from the card

  /**
   * @brief AID applet ID number for later use of selecting specific applet
   */
  const byte AID[12] = {0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x74};
  APDU* SELECT_APPLET_APDU = NULL; //< select applet by AID
  const SCARD_IO_REQUEST determineProtocolStructure(); //< Detect protocol

public:
  /**
   * @brief SCUtils Default constructor.
   *
   * App will connect and establish connection to the card and store
   * _context and _readers.
   */
  SCUtils();
  /**
   * @brief sendToCard Send APDU to the smard card.
   * @param apdu apdu command
   * @param response buffer to recieve response
   * @return SCARD_S_SUCCESS on success, error code otherwise
   */
  LONG sendToCard(const APDU* apdu, APDUResponse* response);
  /**
   * @brief connectToCardAndSetQtSESAMApplet loop over readers and find
   * connected card. Then send APDU command to choose Qt-SESAM applet
   * on card.
   */
  void connectToCardAndSetQtSESAMApplet();
  /**
   * @brief readCardPublicKey read public key and modulus from the card
   * and store it to _cardPublicKey and _cardModulus.
   */
  void readCardPublicKey();
  /**
   * @brief sendAPDUEncryptedByCardPKI send apdu encrypted by card's public key
   * @param apdu apdu buffer to send
   * @param response response buffer to recieve response code
   */
  void sendAPDUEncryptedByCardPKI(APDU* apdu, APDUResponse* response);
  /**
   * @brief SCUtils Default destructor, it deletes applet.
   */
  ~SCUtils();
};

#endif // SCUTILS_H
