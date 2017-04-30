package applets;


import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class QTSesamApplet extends javacard.framework.Applet {

    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_GENERATING_PK_DH = (byte) 0x51;
    final static byte INS_ESTABLISH_SESSION_KEY = (byte) 0x52;
    final static byte INS_TEST = (byte) 0x53;

    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;

    final static byte INS_GET_PUBLIC_KEY = (byte) 0x70;
    final static byte INS_GET_PUBLIC_KEY_MODULUS = (byte) 0x71;

    final static short ARRAY_LENGTH = (short) 0x100;
    final static short KEY_LENGTH = (short) 0x80;
    final static short SESSION_KEY_SIZE = (short) 0x10;

    final static short SW_BAD_PIN = (short) 0x6900;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;
    private OwnerPIN m_pin = null;

    private RandomData m_randomGenerator;
    private Cipher m_dhCipher;

    private RSAPrivateKey m_dhPrivateKey;
    private MessageDigest m_kdf;
    private Cipher m_sessionCipher;
    private AESKey m_sessionKey;

    private Cipher m_cardCipher;
    private RSAPrivateKey m_cardPrivate;
    private RSAPublicKey m_cardPublic;
    private KeyPair m_keyPair;

    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    // PERSISTENT ARRAY IN EEPROM
    boolean m_access = false;
    private byte m_dataArray[] = null;

    /**
     * QTSesamApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected QTSesamApplet(byte[] buffer, short offset, byte length) {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        // Install parameter detail. Compliant with OP 2.0.1.

        // | size | content
        // |------|---------------------------
        // |  1   | [AID_Length]
        // | 5-16 | [AID_Bytes]
        // |  1   | [Privilege_Length]
        // | 1-n  | [Privilege_Bytes] (normally 1Byte)
        // |  1   | [Application_Proprietary_Length]
        // | 0-m  | [Application_Proprietary_Bytes]
        // shift to privilege offset
        dataOffset += (short) (1 + buffer[offset]);
        // finally shift to Application specific offset
        dataOffset += (short) (1 + buffer[dataOffset]);

        // go to proprietary data
        dataOffset++;

        m_dataArray = new byte[ARRAY_LENGTH];
        Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

        m_randomGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_DESELECT);

        m_dhCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        m_dhPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);

        m_kdf = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        m_sessionCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        m_pin = new OwnerPIN((byte) 5, (byte) 4);
        m_pin.update(m_dataArray, (byte) 0, (byte) 4); // set initial random pin

        m_keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1280);
        m_keyPair.genKeyPair();

        // Generate card keypair
        m_cardPublic = (RSAPublicKey) m_keyPair.getPublic();
        m_cardPrivate = (RSAPrivateKey) m_keyPair.getPrivate();

        m_cardCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        m_cardCipher.init(m_cardPrivate, Cipher.MODE_DECRYPT);

        // <PUT YOUR CREATION ACTION HERE>
        // register this instance
        register();
    }

    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new QTSesamApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        // <PUT YOUR SELECTION ACTION HERE>

        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {

        // <PUT YOUR DESELECTION ACTION HERE>
        return;
    }

    /**
     * Method processing an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        //short dataLen = apdu.setIncomingAndReceive();
        //Util.arrayCopyNonAtomic(apduBuffer, (short) 0, m_dataArray, m_apduLogOffset, (short) (5 + dataLen));
        //m_apduLogOffset = (short) (m_apduLogOffset + 5 + dataLen);

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_GET_PUBLIC_KEY:
                        getPublicKey(apdu);
                        break;
                    case INS_GET_PUBLIC_KEY_MODULUS:
                        getModulus(apdu);
                        break;
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_GENERATING_PK_DH:
                        generatePublicDH(apdu);
                        break;
                    case INS_ESTABLISH_SESSION_KEY:
                        establishSessionKey(apdu);
                        break;
                    case INS_TEST:
                        test(apdu);
                        break;

                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }

            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }

    private void test(APDU apdu) {
        short decryptedSize = decryptAPDU(apdu);
        byte[] apdubuf = apdu.getBuffer();

        apdubuf[ISO7816.OFFSET_CDATA] += 1; // GET ENCRYPTED SECRET AND RETURN TECRET

        short paddingSize = encryptWithSessionKey(apdubuf, ISO7816.OFFSET_CDATA, decryptedSize, apdu);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (decryptedSize + paddingSize));
    }

    private void getModulus(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short datalen = apdu.setIncomingAndReceive();

        short size = m_cardPrivate.getModulus(apdubuf, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, size);
    }

    private void getPublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short datalen = apdu.setIncomingAndReceive();

        short size = m_cardPublic.getExponent(apdubuf, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, size);
    }

    private void establishSessionKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short datalen = apdu.setIncomingAndReceive();

        short sessionKeyLength = 0;

        // Decrypt by card private key
        m_cardCipher.init(m_cardPrivate, Cipher.MODE_DECRYPT);
        datalen = m_cardCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, datalen, apdubuf, ISO7816.OFFSET_CDATA);

        // generate sessionKey
        try {
            m_dhCipher.init(m_dhPrivateKey, Cipher.MODE_DECRYPT);
            sessionKeyLength = m_dhCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, datalen, m_ramArray2, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short) 0xF100 | e.getReason()));
        }

        try {
            m_kdf.doFinal(m_ramArray2, (short) 0, sessionKeyLength, m_ramArray, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short) 0xF200 | e.getReason()));
        }

        try {
            m_sessionKey.setKey(m_ramArray, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short) 0xF300 | e.getReason()));
        }
    }

    private void generatePublicDH(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short datalen = apdu.setIncomingAndReceive();

        short m_length = apdubuf[ISO7816.OFFSET_P1];
        short g_length = apdubuf[ISO7816.OFFSET_P2];

        if (m_length < 0) {
            m_length += (short) 256;
        }
        if (g_length < 0) {
            g_length += (short) 265;
        }

        Util.arrayFillNonAtomic(m_ramArray2, (short) 0, KEY_LENGTH, (byte) 0);
        Util.arrayCopyNonAtomic(apdubuf, (short) (ISO7816.OFFSET_CDATA + m_length), m_ramArray2, (short) (KEY_LENGTH - g_length), g_length);


        // generate privatePart of dh
        try {
            m_randomGenerator.generateData(m_ramArray, (short) 0, KEY_LENGTH);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short)0xF100 | e.getReason()));
        }

        try {
            m_dhPrivateKey.setModulus(apdubuf, ISO7816.OFFSET_CDATA, m_length);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short)0xF200 | e.getReason()));
        }

        try {
            m_dhPrivateKey.setExponent(m_ramArray, (short) 0, KEY_LENGTH);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short)0xF300 | e.getReason()));
        }

        try {
            // generate publicPart of dh
            m_dhCipher.init(m_dhPrivateKey, Cipher.MODE_DECRYPT);
            short publicPartSize = m_dhCipher.doFinal(m_ramArray2, (short) 0, KEY_LENGTH, m_ramArray, (short) 0);
            Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, publicPartSize);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, publicPartSize);
        } catch (CryptoException e) {
            ISOException.throwIt((short) ((short)0xF400 | e.getReason()));
        }
    }

    private short decryptAPDU(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short datalen = apdu.setIncomingAndReceive();

        // Decrypt and set size to new value
        m_sessionCipher.init(m_sessionKey, Cipher.MODE_DECRYPT);
        m_sessionCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, datalen, apdubuf, ISO7816.OFFSET_CDATA);
        apdubuf[ISO7816.OFFSET_LC] = (byte) (apdubuf[ISO7816.OFFSET_LC] - apdubuf[(short) (ISO7816.OFFSET_CDATA + datalen - 1)]);
        return apdubuf[ISO7816.OFFSET_LC];
    }


    private byte encryptWithSessionKey(byte[] src, byte from, short size, APDU apdu) {
        byte paddingSize = (byte) (16 - (size % 16));

        for (short i = 0; i < paddingSize; i++) {
            src[(short) (from + size + i)] = paddingSize;
        }

        m_sessionCipher.init(m_sessionKey, Cipher.MODE_ENCRYPT);
        m_sessionCipher.doFinal(src, from, (short) (size + paddingSize), src, from);

        return paddingSize;
    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // VERIFY PIN
        if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            ISOException.throwIt(SW_BAD_PIN);
            m_access = false;
        } else {
            m_access = true;
        }
    }

    // SET PIN 
    // Be aware - this method will allow attacker to set own PIN - need to protected. 
    // E.g., by additional Admin PIN or all secret data of previous user needs to be reased 
    void SetPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        //set pin only after verifying an old one

        /* implementation of verifying pin and then setting a new one from apdu */
        // SET NEW PIN
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

}
