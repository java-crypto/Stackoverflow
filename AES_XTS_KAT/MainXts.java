package AES_XTS;

import org.bouncycastle.crypto.params.KeyParameter;
import java.util.Arrays;

public class MainXts {
    public static void main(String[] args) {
        System.out.println("AES XTS Known Answer Text");
        System.out.println("get testvectors: " +
        "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/XTSTestVectors.zip");
        System.out.println("Basis: https://github.com/horrorho/Java-XTS-AES/");
        byte[] key, plaintext, ciphertextExpected, ciphertext, decrypttext;
        long dataUnitSeqNumber;
        XTSAESCipher cipher = new XTSAESCipher();
        KeyParameter keyParam1, keyParam2;

        System.out.println("\nTestvector 1 Encrypt"); // 'format tweak value input - data unit seq no' XTSGenAES128.rsp
        key = hexStringToByteArray("a3e40d5bd4b6bbedb2d18c700ad2db2210c81190646d673cbca53f133eab373c");
        dataUnitSeqNumber = 141L;
        plaintext = hexStringToByteArray("20e0719405993f09a66ae5bb500e562c");
        ciphertextExpected = hexStringToByteArray("74623551210216ac926b9650b6d3fa52");
        // split key in two parts
        int keyLength = key.length;
        byte[] key1 = new byte[keyLength / 2];
        byte[] key2 = new byte[keyLength / 2];
        System.arraycopy(key, 0, key1, 0, key1.length);
        System.arraycopy(key, key1.length, key2, 0, key2.length);
        //System.out.println("key:  " + key.length + " data: " + bytesToHex(key));
        //System.out.println("key1: " + key1.length + " data: " + bytesToHex(key1));
        //System.out.println("key2: " + key2.length + " data: " + bytesToHex(key2));
        ciphertext = new byte[plaintext.length];
        keyParam1 = new KeyParameter(key1);
        keyParam2 = new KeyParameter(key2);
        // encrypt
        int bytesProcessed = cipher.init(true, keyParam1, keyParam2)
                .processDataUnit(plaintext, 0, plaintext.length, ciphertext, 0, dataUnitSeqNumber);
        System.out.println("dataUnitSeqNumber: " + dataUnitSeqNumber);
        System.out.println("ciphertext     : " + bytesToHex(ciphertext));
        System.out.println("ciphertext exp : " + bytesToHex(ciphertextExpected));
        System.out.println("ciphertext equals expected: " + Arrays.equals(ciphertext, ciphertextExpected));
        // decrypt
        decrypttext = new byte[ciphertext.length];
        bytesProcessed = cipher.init(false, keyParam1, keyParam2)
                .processDataUnit(ciphertext, 0, ciphertext.length, decrypttext, 0, dataUnitSeqNumber);
        System.out.println("decrypttext    : " + bytesToHex(decrypttext));
        System.out.println("plainttext     : " + bytesToHex(plaintext));
        System.out.println("decryptext equals plaintext: " + Arrays.equals(decrypttext, plaintext));

        System.out.println("\nTestvector 500 Encrypt");
        key = hexStringToByteArray("16444b90c4266d8b0b464ad0963f5c605074c61d33e9becf6f31e277aeb02ee7");
        dataUnitSeqNumber = 139L;
        plaintext = hexStringToByteArray("a788b66ebb4b38a43e709be5b58e5baf7c0f814c2a0e78c297f4ac0ff902a880");
        ciphertextExpected = hexStringToByteArray("4d675587337e89bbd356e63da54970820a28f076c4bd1e30277f584a30a82081");
        ciphertext = new byte[plaintext.length];
        keyLength = key.length;
        key1 = new byte[keyLength / 2];
        key2 = new byte[keyLength / 2];
        System.arraycopy(key, 0, key1, 0, key1.length);
        System.arraycopy(key, key1.length, key2, 0, key2.length);
        //System.out.println("key:  " + key.length + " data: " + bytesToHex(key));
        //System.out.println("key1: " + key1.length + " data: " + bytesToHex(key1));
        //System.out.println("key2: " + key2.length + " data: " + bytesToHex(key2));
        keyParam1 = new KeyParameter(key1);
        keyParam2 = new KeyParameter(key2);
        // encrypt
        bytesProcessed = cipher.init(true, keyParam1, keyParam2)
                .processDataUnit(plaintext, 0, plaintext.length, ciphertext, 0, dataUnitSeqNumber);
        System.out.println("dataUnitSeqNumber: " + dataUnitSeqNumber);
        System.out.println("ciphertext     : " + bytesToHex(ciphertext));
        System.out.println("ciphertext exp : " + bytesToHex(ciphertextExpected));
        System.out.println("ciphertext equals expected: " + Arrays.equals(ciphertext, ciphertextExpected));
        // decrypt
        decrypttext = new byte[ciphertext.length];
        bytesProcessed = cipher.init(false, keyParam1, keyParam2)
                .processDataUnit(ciphertext, 0, ciphertext.length, decrypttext, 0, dataUnitSeqNumber);
        System.out.println("decrypttext    : " + bytesToHex(decrypttext));
        System.out.println("plainttext     : " + bytesToHex(plaintext));
        System.out.println("decryptext equals plaintext: " + Arrays.equals(decrypttext, plaintext));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}

