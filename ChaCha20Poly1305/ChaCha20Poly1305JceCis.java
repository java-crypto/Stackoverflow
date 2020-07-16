package ChaCha20_Poly1305_fails_with_ShortBufferException_Output_buffer_too_small;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.Arrays;

public class ChaCha20Poly1305JceCis {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.println("File En-/Decryption with ChaCha20-Poly1305 JCE");
        System.out.println("see: https://stackoverflow.com/questions/61520639/chacha20-poly1305-fails-with-shortbufferexception-output-buffer-too-small");
        System.out.println("\njava version: " + Runtime.version());
        String filenamePlain = "test1024.txt";
        String filenameEnc = "test1024enc.txt";
        String filenameDec = "test1024dec.txt";
        Files.deleteIfExists(new File(filenamePlain).toPath());
        generateRandomFile(filenamePlain, 1024);
        // setup chacha20-poly1305-cipher
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] key = new byte[32]; // 32 for 256 bit key or 16 for 128 bit
        byte[] nonce = new byte[12]; // nonce = 96 bit
        sr.nextBytes(key);
        sr.nextBytes(nonce);

        System.out.println("start encryption");
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        try (FileInputStream in = new FileInputStream(filenamePlain);
             FileOutputStream out = new FileOutputStream(filenameEnc);
             CipherOutputStream encryptedOutputStream = new CipherOutputStream(out, cipher);) {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "ChaCha20");
            System.out.println("keySpec: " + secretKeySpec.getAlgorithm() + " " + secretKeySpec.getFormat());
            System.out.println("cipher algorithm: " + cipher.getAlgorithm());
            //AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(nonce));
            byte[] buffer = new byte[8096];
            int nread;
            while ((nread = in.read(buffer)) > 0) {
                encryptedOutputStream.write(buffer, 0, nread);
            }
            encryptedOutputStream.flush();
        }

        // decryption
        System.out.println("start decryption");
        Cipher cipherD = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        try (FileInputStream in = new FileInputStream(filenameEnc); // i don't care about the path as all is lokal
             CipherInputStream cipherInputStream = new CipherInputStream(in, cipherD);
             FileOutputStream out = new FileOutputStream(filenameDec)) // i don't care about the path as all is lokal
        {
            byte[] buffer = new byte[8192];
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "ChaCha20");
            //AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(nonce);
            cipherD.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(nonce));
            int nread;
            while ((nread = cipherInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, nread);
            }
            out.flush();
        }

        // file compare
        System.out.println("compare plain <-> dec: " + Arrays.equals(sha256(filenamePlain), sha256(filenameDec)));
    }

    public static void generateRandomFile(String filename, int size) throws IOException, NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] data = new byte[size];
        sr.nextBytes(data);
        Files.write(Paths.get(filename), data, StandardOpenOption.CREATE);
    }

    public static byte[] sha256(String filenameString) throws IOException, NoSuchAlgorithmException {
        byte[] buffer = new byte[8192];
        int count;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filenameString));
        while ((count = bis.read(buffer)) > 0) {
            md.update(buffer, 0, count);
        }
        bis.close();
        return md.digest();
    }
}