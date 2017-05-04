package fingerprint.generator;

import javacard.security.MessageDigest;

import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author xsvenda
 */
public class FingerprintCounter {

    static CardMngr cardManager = new CardMngr();

    private static byte APPLET_AID[] = {
            (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70,
            (byte) 0x6C, (byte) 0x65, (byte) 0x61, (byte) 0x70,
            (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74
    };
    private static byte SELECT_QTSESAMAPPLET[] = {
            (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0b, (byte) 0x73, (byte) 0x69, (byte) 0x6D,
            (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x61,
            (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65,
            (byte) 0x74
    };

    public static void main(String[] args) {
        try {
            //
            // THIS NEEDS TO RUN IN SECURE ENVIRONMENT !!!!
            //

            if (cardManager.ConnectToCard()) {
                cardManager.sendAPDU(SELECT_QTSESAMAPPLET);

                byte apdu[] = new byte[CardMngr.HEADER_LENGTH];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x70;
                apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) 0x00;

                ResponseAPDU publicKeyOutput = cardManager.sendAPDU(apdu);
                byte[] publicKeyArray = publicKeyOutput.getData();

                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x71;
                apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) 0x00;

                ResponseAPDU modulusOutput = cardManager.sendAPDU(apdu);
                byte[] modulusArray = modulusOutput.getData();

                // concat both into one
                byte[] inputToHash = new byte[publicKeyArray.length + modulusArray.length];

                System.arraycopy(publicKeyArray, 0, inputToHash, 0, publicKeyArray.length);
                System.arraycopy(modulusArray, 0, inputToHash, publicKeyArray.length, modulusArray.length);

                MessageDigest sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
                byte[] output = new byte[32];
                sha256.doFinal(inputToHash, (short) 0, (short) inputToHash.length, output, (short) 0);

                // dynamic truncation
                int offset   =  output[31] & 0xf ;
                int bin_code = (output[offset]  & 0x7f) << 24
                        | (output[offset+1] & 0xff) << 16
                        | (output[offset+2] & 0xff) <<  8
                        | (output[offset+3] & 0xff) ;

                int fingerprint = bin_code % 1000000;

                System.out.println("Fingerprint of your card is: " + fingerprint);

                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }


        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
