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
  CryptoPP::Integer _modulus;
  CryptoPP::Integer _order;
  CryptoPP::Integer _generator;

  CryptoPP::SecByteBlock _privatePart;
  CryptoPP::SecByteBlock _publicPart;
  CryptoPP::SecByteBlock _sessionKey;

  CryptoPP::AES::Decryption* _aesDecryption = NULL;
  CryptoPP::AES::Encryption* _aesEncryption = NULL;
  CryptoPP::CBC_Mode_ExternalCipher::Decryption _decryptor;
  CryptoPP::CBC_Mode_ExternalCipher::Encryption _encryptor;

  SCUtils* _smartCard;

  byte _iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

public:
  SecureChannel(SCUtils* sc);

  APDUResponse sendToCardSecurely(APDU* apdu);

  void encrypt(byte* src, int srcSize, byte** dest, int* destSize);
  void encrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest);
  void decrypt(byte* src, int srcSize, byte** dest, int* destSize);
  void decrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest);

  ~SecureChannel() {
    delete _aesDecryption;
    delete _aesEncryption;
  }
};

#endif // SECURECHANNEL_H
