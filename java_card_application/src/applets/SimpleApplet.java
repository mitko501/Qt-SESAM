package applets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimpleApplet extends javacard.framework.Applet {

    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_DECRYPT = (byte) 0x51;
    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;
    final static byte INS_RETURNDATA = (byte) 0x57;
    final static byte INS_GETAPDUBUFF = (byte) 0x59;
    final static byte INS_SENDPUBLICKEY = (byte) 0x60;

    final static short ARRAY_LENGTH = (short) 0xff;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_CANT_ACCES_HOTP = (short) 0x6712;
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

    private Cipher m_decryptCipher = null;
    private OwnerPIN m_pin = null;
    private KeyPair m_keyPair = null;
    private Key m_privateKey = null;
    private Key m_publicKey = null;

    boolean m_access = false;
    private short m_apduLogOffset = (short) 0;
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * SimpleApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length) {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if (length > 9) {
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

            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
            m_keyPair.genKeyPair();
            m_publicKey = m_keyPair.getPublic();
            m_privateKey = m_keyPair.getPrivate();

            m_decryptCipher = Cipher.getInstance(Cipher.ALG_RSA_ISO14888, false);
            m_decryptCipher.init(m_privateKey, Cipher.MODE_DECRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4); // set initial random pin

            // update flag
            isOP2 = true;

        } else {
            // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
            // if(length != <PUT YOUR PARAMETERS LENGTH> )
            //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
        }

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
        new SimpleApplet(bArray, bOffset, bLength);
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
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_SENDPUBLICKEY:
                        SendPublicKey(apdu);
                        break;
                    case INS_DECRYPT:
                        Decrypt(apdu);
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

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        short i;

        // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // DECRYPT INCOMING BUFFER
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

        // COPY DECRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void SendPublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        /* do magic */
        //http://stackoverflow.com/questions/32996318/convert-object-to-byte-in-java-card
        //set size, length, exponent and modulus to byte array and send it, 
        //then store in application qt-sesam in some struct

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        //Util.arrayCopyNonAtomic(m_publicKey, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_apduLogOffset);
        //short tempLength = m_apduLogOffset;
        //m_apduLogOffset = 0;
        // SEND OUTGOING BUFFER
        //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, tempLength);     
    }

}
