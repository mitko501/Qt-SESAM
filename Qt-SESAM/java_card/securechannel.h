#ifndef SECURECHANNEL_H
#define SECURECHANNEL_H

#include "dh.h"
#include "scutils.h"
#include "osrng.h"
#include "nbtheory.h"
#include "sha.h"
#include "aes.h"
#include "modes.h"


class SecureChannel
{
private:
  CryptoPP::Integer _modulus; //< Hardcoded modulus of DH (due to performance)
  CryptoPP::Integer _order; //< Hardcoded order of DH (due to performance)
  CryptoPP::Integer _generator; //< Generator of DH

  CryptoPP::SecByteBlock _privatePart; //< Private key
  CryptoPP::SecByteBlock _publicPart; //< Public key
  CryptoPP::SecByteBlock _sessionKey; //< Session key

  CryptoPP::AES::Decryption* _aesDecryption = NULL; //< Decryption function with session key
  CryptoPP::AES::Encryption* _aesEncryption = NULL; //< Encryption function with session key
  CryptoPP::CBC_Mode_ExternalCipher::Decryption* _decryptor; //< Decryption in CBC Mode
  CryptoPP::CBC_Mode_ExternalCipher::Encryption* _encryptor; //< Encryption in CBC Mode

  SCUtils* _smartCard; //< Connected smart card

  byte _iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; //< Initializing vector

public:
  /**
   * @brief SecureChannel establish secure channel for exchanging password
   * between application and smartcard. Protocol is used Diffie-Hellman.
   * @param sc connected smartcard
   */
  SecureChannel(SCUtils* sc);
  /**
   * @brief sendToCardSecurely encrypt apdu by session key and send it to card
   * @param apdu apdu to encrypy
   * @return response buffer
   */
  APDUResponse sendToCardSecurely(APDU* apdu);
  void encrypt(byte* src, int srcSize, byte** dest, int* destSize);
  void encrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest);
  void decrypt(byte* src, int srcSize, byte** dest, int* destSize);
  void decrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest);
  /**
   * @brief SecureChannel defaul destructor. Free up memory.
   */
  ~SecureChannel() {
    delete _aesDecryption;
    delete _aesEncryption;

    delete _encryptor;
    delete _decryptor;
  }
};

#endif // SECURECHANNEL_H
