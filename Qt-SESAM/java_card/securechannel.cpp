#include "securechannel.h"

SecureChannel::SecureChannel(SCUtils* sc) : _smartCard(sc) {
  // Establishing secure channel

  // Generate new dh config
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::DH dh;

  _modulus = CryptoPP::Integer("0x985dc68eef5c5ae2f2b58b9d86de4fdcf9ba99b355814f580a486d14fb1ed53b8c04e8e3adba662f55fb326c105536caab9eaa7f29eb813c63418287bae572cf9df8c5a7cb95e91c0214f85098f7641e2cb556a11409a1e2d93a6c0eaec573fd933aca969aa0c4660506f8116b1436745472b840e1ca20b36fbca8ae01a947a3");
  _order = CryptoPP::Integer("0x4c2ee34777ae2d71795ac5cec36f27ee7cdd4cd9aac0a7ac0524368a7d8f6a9dc6027471d6dd3317aafd9936082a9b6555cf553f94f5c09e31a0c143dd72b967cefc62d3e5caf48e010a7c284c7bb20f165aab508a04d0f16c9d36075762b9fec99d654b4d50623302837c08b58a1b3a2a395c2070e51059b7de545700d4a3d1");
  _generator = CryptoPP::Integer(3);

  dh.AccessGroupParameters().Initialize(_modulus, _order, _generator);

  _modulus = dh.GetGroupParameters().GetModulus();
  _generator = dh.GetGroupParameters().GetSubgroupGenerator();
  _order = dh.GetGroupParameters().GetSubgroupOrder();

  _privatePart = CryptoPP::SecByteBlock(dh.PrivateKeyLength());
  _publicPart = CryptoPP::SecByteBlock(dh.PublicKeyLength());
  _sessionKey = CryptoPP::SecByteBlock(dh.AgreedValueLength());

  dh.GenerateKeyPair(rng, _publicPart, _privatePart);

  // Library function, doesn't work, so I need to generate public info myself
  CryptoPP::Integer intPrivate(_privatePart.data(), _privatePart.size());
  CryptoPP::Integer intPublic = CryptoPP::ModularExponentiation(_generator, intPrivate, _modulus);
  byte publicChars[intPublic.ByteCount()]; // Cast Integer to SecByteBlock
  intPublic.Encode(publicChars, intPublic.ByteCount());
  _publicPart = CryptoPP::SecByteBlock(publicChars, intPublic.ByteCount());

  // Send dh config to card
  APDU secureChannelRequest(0x51); // 0x51 instruction for secure channel establishing on card

  secureChannelRequest.add_data(_modulus);
  secureChannelRequest.set_p1(_modulus.ByteCount());

  secureChannelRequest.add_data(_generator);
  secureChannelRequest.set_p2(_generator.ByteCount());

  APDUResponse publicAlicaInfo;
  sc->sendToCard(&secureChannelRequest, &publicAlicaInfo);

  if (!publicAlicaInfo.isSuccessful()) {
    printf("Can't receive public info of card! Error: (%04x)\n", publicAlicaInfo.getStatusCode());
  }

  APDU publicKeyAPDU(0x52);
  publicKeyAPDU.add_data(_publicPart);

  APDUResponse sessionKeyAgreed;
  sc->readCardPublicKey();
  sc->sendAPDUEncryptedByCardPKI(&publicKeyAPDU, &sessionKeyAgreed);

  if (!sessionKeyAgreed.isSuccessful()) {
    printf("Alica didn't agree in DH! Error: (%04x)\n", sessionKeyAgreed.getStatusCode());
  }

  //Agree on one key, alica will always get the same result
  if (!dh.Agree(_sessionKey, _privatePart, publicAlicaInfo.asSecByteBlock())) {
      std::cout << "it's wrong!!!" << std::endl;
  }

  // Derivate session key from dh output using SHA256
  CryptoPP::SHA256 kdf;

  byte shaOutput[32];
  kdf.CalculateDigest(shaOutput, _sessionKey.data(), _sessionKey.size());

  _sessionKey = CryptoPP::SecByteBlock(shaOutput, 16);

  _aesDecryption = new CryptoPP::AES::Decryption(_sessionKey.data(), 16);
  _decryptor = CryptoPP::CBC_Mode_ExternalCipher::Decryption(*_aesDecryption, _iv);

  _aesEncryption = new CryptoPP::AES::Encryption(_sessionKey.data(), 16);
  _encryptor = CryptoPP::CBC_Mode_ExternalCipher::Encryption(*_aesEncryption, _iv);
}

APDUResponse SecureChannel::sendToCardSecurely(APDU* apdu) {
  APDU encryptedAPDU(apdu->get_class(), apdu->get_ins(), apdu->get_p1(), apdu->get_p2(),
                     0x00, NULL);
  if (apdu->dataSize() != 0) {
    CryptoPP::SecByteBlock encryptedData;

    encrypt(apdu->getDataPtr(), apdu->dataSize(), &encryptedData);

    encryptedAPDU.add_data(encryptedData);
  }

  APDUResponse encryptedResponse;

  _smartCard->sendToCard(&encryptedAPDU, &encryptedResponse);


  if (encryptedResponse.size() != 0 && encryptedResponse.isSuccessful()) {
    CryptoPP::SecByteBlock decryptedResponse;
    decrypt(encryptedResponse.response(), encryptedResponse.size(), &decryptedResponse);

    strncpy((char*)encryptedResponse.response(), (char*)decryptedResponse.data(), decryptedResponse.size());
    strncpy((char*) encryptedResponse.response() + decryptedResponse.size(),
            (char*)encryptedResponse.response() + encryptedResponse.size(), 2); // COPY Status code of encrypted response
    (*(encryptedResponse.sizePtr())) = decryptedResponse.size() + 2;
  }

  return encryptedResponse;
}

void SecureChannel::encrypt(byte* src, int srcSize, byte** dest, int* destSize) {
  // padding
  int paddingSize = 16 - srcSize % 16;

  (*dest) = (byte*) malloc(srcSize + paddingSize);

  if ((*dest) == NULL) {
    printf("Can't allocate memory\n");
    exit(0);
  }

  strncpy((char*)(*dest), (char*) src, srcSize);

  for(int i = 0; i < paddingSize; i++) {
    (*dest)[srcSize + i] = paddingSize;
  }

  _encryptor.ProcessData((*dest), (*dest), srcSize + paddingSize);
  _encryptor.Resynchronize(_iv);

  (*destSize) = srcSize + paddingSize;
}

void SecureChannel::encrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest) {
  byte* encrypted = NULL;
  int size = 0;

  encrypt(src, srcSize, &encrypted, &size);

  CryptoPP::SecByteBlock decryptedBlock(encrypted, size);
  (*dest) = decryptedBlock;

  free(encrypted);
}

void SecureChannel::decrypt(byte* src, int srcSize, CryptoPP::SecByteBlock* dest) {
  byte* decrypted = NULL;
  int size = 0;

  decrypt(src, srcSize, &decrypted, &size);

  CryptoPP::SecByteBlock decryptedBlock(decrypted, size);
  (*dest) = decryptedBlock;

  free(decrypted);
}

void SecureChannel::decrypt(byte* src, int srcSize, byte** dest, int* destSize) {
  (*dest) = (byte*) malloc(srcSize);

  if ((*dest) == NULL) {
    printf("Can't allocate memory\n");
    exit(0);
  }

  _decryptor.ProcessData((*dest), src, srcSize);
  _decryptor.Resynchronize(_iv);

  (*destSize) = srcSize - (*dest)[srcSize - 1]; // Size without padding
}

