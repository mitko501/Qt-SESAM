package simpleapdu;

import applets.QTSesamApplet;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {

    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };
    private static byte NEW_USER_PIN[] = {
            (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31
    };
    private static byte APPLET_AID[] = {
            (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70,
            (byte) 0x6C, (byte) 0x65, (byte) 0x61, (byte) 0x70,
            (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74
    };
    private static byte SELECT_SIMPLEAPPLET[] = {
            (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0b, (byte) 0x73, (byte) 0x69, (byte) 0x6D,
            (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x61,
            (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65,
            (byte) 0x74
    };

    public static void main(String[] args) {
        try {
            // Prepare simulated card - key
            byte[] installData = {
                    (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33,
                    (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,
                    (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                    (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
            };

            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData,
                    QTSesamApplet.class);

            byte[] challenge = new byte[20];
            for (int i = 0; i < challenge.length; i++) {
                challenge[i] = (byte) i;
            }

            short additionalDataLen = (short) challenge.length;

            byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            Util.arrayCopyNonAtomic(challenge, (short) 0, apdu,
                    CardMngr.OFFSET_DATA, additionalDataLen);

            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x60; //INS_GENERATE_HOTP
            apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            byte[] response = cardManager.sendAPDUSimulator(apdu);
            System.out.println(CardMngr.bytesToHex(response));

            //long time = 0;
            //for (int i = 0; i < 100; i++) {
            /*
            if (cardManager.ConnectToCard()) {
                // Select our application on card
                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                //long startTime = System.nanoTime();
                cardManager.sendAPDU(apdu);
                //long stopTime = System.nanoTime();
                //time += stopTime - startTime;
                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }
            */
            //}
            //System.out.println(time / 100);

            byte apdu1[] = new byte[CardMngr.HEADER_LENGTH +
                    DEFAULT_USER_PIN.length];
            Util.arrayCopyNonAtomic(DEFAULT_USER_PIN, (short) 0, apdu,
                    CardMngr.OFFSET_DATA, (short) DEFAULT_USER_PIN.length);
            apdu1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu1[CardMngr.OFFSET_INS] = (byte) 0x55; //INS_VERIFYPIN
            apdu1[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu1[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu1[CardMngr.OFFSET_LC] = (byte) DEFAULT_USER_PIN.length;
            byte[] response1 = cardManager.sendAPDUSimulator(apdu1);
            System.out.println(CardMngr.bytesToHex(response1));
//
//            if (cardManager.ConnectToCard()) {
//                // Select our application on card
//                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
//                //long startTime = System.nanoTime();
//                cardManager.sendAPDU(apdu1);
//                //long stopTime = System.nanoTime();
//                cardManager.DisconnectFromCard();
//            } else {
//                System.out.println("Failed to connect to card");
//            }
            byte apdu2[] = new byte[CardMngr.HEADER_LENGTH];
            apdu2[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu2[CardMngr.OFFSET_INS] = (byte) 0x62; //INS_READ_HOTP
            apdu2[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu2[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu2[CardMngr.OFFSET_LC] = (byte) 0;
            byte[] hotp = cardManager.sendAPDUSimulator(apdu2);
            System.out.println(CardMngr.bytesToHex(hotp));
//
//            if (cardManager.ConnectToCard()) {
//                // Select our application on card
//                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
//                //long startTime = System.nanoTime();
//                cardManager.sendAPDU(apdu2);
//                //long stopTime = System.nanoTime();
//                cardManager.DisconnectFromCard();
//            } else {
//                System.out.println("Failed to connect to card");
//            }

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
