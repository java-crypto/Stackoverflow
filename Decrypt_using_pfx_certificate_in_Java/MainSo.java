package Decrypt_using_pfx_certificate_in_Java;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

public class MainSo {
    public static void main(String[] args) throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException {
        System.out.println("https://stackoverflow.com/questions/62769422/decrypt-using-pfx-certificate-in-java?noredirect=1#comment111047725_62769422");
        System.out.println("RSA decryption using a pfx keystore");
        //byte[] file = Files.readAllBytes(Paths.get("C:/file.fileinfo"));
        byte[] file = Files.readAllBytes(Paths.get("fileinfo"));
        // password for keystore access and private key + certificate access
        String pfxPassword = "pwd";
        String keyAlias = "pvktmp:1ce254e5-4620-4abf-9a12-fbbda5b97fa0";
        // load keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        //keystore.load(inputStream, pfxPassword.toCharArray());
        keystore.load(new FileInputStream("keystore.pfx"), pfxPassword.toCharArray());
        PrivateKey key = (PrivateKey) keystore.getKey(keyAlias, pfxPassword.toCharArray());
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key);
        System.out.println(new String(cipher.doFinal(file)));
    }
}
