package PGP_Encryption_after_Update_Not_Working;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class PGPMain {
    public static void main(String[] args) throws NoSuchProviderException, IOException, PGPException {
        System.out.println("https://stackoverflow.com/questions/61927913/bouncycastle-update-from-1-46-to-1-56-not-working");
        Security.addProvider(new BouncyCastleProvider()); // get bouncy castle: https://www.bouncycastle.org/latest_releases.html
        // you need the bcprov-jdk15to18-165.jar and bcpg-jdk15on-165.jar at the time of writing
        System.out.println("\nJava version: " + Runtime.version() + " BouncyCastle Version: " + Security.getProvider("BC"));
        // create a keypair with RSAKeyPairGenerator.java

        // encryption
        KeyBasedLargeFileProcessor.encryptFile("enc.txt", "plain.txt", "pub.asc", false, true);

        // rename plaintextfile as it will be overwritten by decryptFile (filename is stored within encrypted file)
        File file = new File("plain.txt");
        file.renameTo(new File("plain_org.txt"));

        // decryption will generate the decrypted file with original filename !
        KeyBasedLargeFileProcessor.decryptFile("enc.txt", "secret.asc", "mypassphrase".toCharArray(), "defaultfilename.txt");
        // return the original filename, to change this behavior change the code in class KeyBasedLargeFileProcessor lines 142-146
    }
}
