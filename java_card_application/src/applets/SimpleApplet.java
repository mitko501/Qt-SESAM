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
    final static byte INS_ENCRYPT = (byte) 0x50;
    final static byte INS_DECRYPT = (byte) 0x51;
    final static byte INS_SETKEY = (byte) 0x52;
    final static byte INS_HASH = (byte) 0x53;
    final static byte INS_RANDOM = (byte) 0x54;
    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;
    final static byte INS_RETURNDATA = (byte) 0x57;
    final static byte INS_SIGNDATA = (byte) 0x58;
    final static byte INS_GETAPDUBUFF = (byte) 0x59;
    final static byte INS_GENERATE_HOTP = (byte) 0x60;
    final static byte INS_READ_HOTP = (byte) 0x62;

    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

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

    private AESKey m_aesKey = null;
    private MessageDigest m_hash = null;
    private OwnerPIN m_pin = null;

    //temporary array in ram
    private byte m_hotp[] = null;
    //flag for accesing m_hotp
    boolean m_access = false;
    private short m_apduLogOffset = (short) 0;
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
//            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            Util.arrayCopyNonAtomic(buffer, offset, m_dataArray, (short) 0, length);

            // CREATE AES KEY OBJECT
            // Applet will accept new secret key K later used to produce OTP (infrequent)
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            //m_hotp = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);

            // STORE KEY FROM INSTALLATION
            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);

            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin

            byte default_user_pin[] = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            };

            m_pin.update(default_user_pin, (byte) 0, (byte) 4); // set initial random pin

            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

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
                    case INS_SETKEY:
                        SetKey(apdu);
                        break;
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_GENERATE_HOTP:
                        GenHOTP(apdu);
                        break;
                    case INS_READ_HOTP:
                        ReadHOTP(apdu);
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

    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH
        if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_128) {
            ISOException.throwIt(SW_KEY_LENGTH_BAD);
        }

        // SET KEY VALUE
        m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);
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

        // SET NEW PIN
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    void GenHOTP(APDU apdu) throws IOException {

        //Applet receives input challenge C from PC and produce corresponding 
        //apdu buff is our challenge/counter 'C'
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        //Computing HMAC(K,C) = SHA1(K ⊕ 0x5c5c… ∥ SHA1(K ⊕ 0x3636… ∥ C))
        //Block length of AES is 16-bytes (128bits) so length of block is 16
        byte[] opad = new byte[16];
        byte[] ipad = new byte[16];
        Util.arrayFillNonAtomic(opad, (short) 0, (short) 16, (byte) 0x5c);
        Util.arrayFillNonAtomic(ipad, (short) 0, (short) 16, (byte) 0x36);

        //Load key to variable
        byte[] key = new byte[16];
        m_aesKey.getKey(key, (short) 0);

        //Computing first part of concatinetion (K ⊕ 0x5c5c…)
        byte[] first = new byte[16];

        //K ⊕ 0x5c5c…
        for (short i = 0; i < opad.length; i++) {
            first[i] = (byte) (key[i] ^ opad[i]);
        }

        //Computing second part of concatinetion SHA1(K ⊕ 0x3636… ∥ C)
        byte[] second = new byte[(short) (16 + dataLen)];

        //K ⊕ 0x3636…
        for (short i = 0; i < ipad.length; i++) {
            second[i] = (byte) (key[i] ^ ipad[i]);
        }

        //K ⊕ 0x3636… ∥ C
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, second,
                (short) ipad.length, dataLen);

        //SHA1(K ⊕ 0x3636… ∥ C)
        if (m_hash != null) {
            m_hash.doFinal(second, (short) 0, (short) second.length, second, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        //Computing final HMAC(K,C) = SHA1(K ⊕ 0x5c5c… ∥ SHA1(K ⊕ 0x3636… ∥ C))
        byte[] hmac = new byte[20];
        byte[] tmp = new byte[(short) (first.length + second.length)];

        //(K ⊕ 0x5c5c…) ∥ SHA1(K ⊕ 0x3636… ∥ C)
        Util.arrayCopyNonAtomic(first, (short) 0, tmp,
                (short) 0, (short) first.length);
        Util.arrayCopyNonAtomic(second, (short) 0, tmp,
                (short) first.length, (short) second.length);

        //SHA1(K ⊕ 0x5c5c… ∥ SHA1(K ⊕ 0x3636… ∥ C))
        if (m_hash != null) {
            m_hash.doFinal(tmp, (short) 0, (short) tmp.length, hmac, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }
        //HMAC(K,C) is done

        //Computing HOTP(K,C) = Truncate(HMAC(K,C)) & 0x7FFFFFFF
        //Following [RFC4226 5.3] for truncate function
        short offset = (short) (hmac[19] & 0xf);
        m_hotp[0] = (byte) (hmac[offset] & 0x7f);
        m_hotp[1] = (byte) (hmac[(short) (offset + 1)] & 0xff);
        m_hotp[2] = (byte) (hmac[(short) (offset + 2)] & 0xff);
        m_hotp[3] = (byte) (hmac[(short) (offset + 3)] & 0xff);
        //HOTP(K,C) is done
/*

        //Compute HOTP-value = combine pair of bytes together to get 2 byte long value
        //Copy HOTP into outgoing buffer
        //Util.arrayCopyNonAtomic(m_hotp, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 4);
        //Send outgoing buffer
        //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 4);
        apdu.setOutgoingAndSend((short) 0, (short) 0);
         */

    }

    void ReadHOTP(APDU apdu) throws IOException {
        byte[] apdubuf = apdu.getBuffer();
        if (m_access) {
            m_access = false;
            Util.arrayCopyNonAtomic(m_hotp, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 4);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 4);
        } else {
            ISOException.throwIt(SW_CANT_ACCES_HOTP);
        }

    }

}
