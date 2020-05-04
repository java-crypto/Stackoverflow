package XMSS_Renew_Usages;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

import java.security.*;
// get bouncycastle version 1.65 here:
// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on/1.65

public class XMSSRenewUsages {
    public static void main(String[] args)
            throws Exception {
        // adds BC + BCPQC to the end of the precedence list
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("stackoverflow - how to renew a XMSS private key?");
        System.out.println("see: https://stackoverflow.com/questions/61595184/xmss-renewing-of-remaining-usages-of-private-keys-possible");

        // generate xmss keypair
        System.out.println("\ngenerate XMSS KeyPair [lasts some seconds...]");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSS", "BCPQC");
        kpg.initialize(XMSSParameterSpec.SHA2_20_256); //  usages
        // changing the spec to '16' or '20' will take much more time to create a keypair
        //kpg.initialize(XMSSParameterSpec.SHA2_16_256); // 65536 usages
        //kpg.initialize(XMSSParameterSpec.SHA2_20_256); // 1048575 usages
        KeyPair kp = kpg.generateKeyPair();

        // some statistics
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();
        XMSSPrivateKey xmssPrivateKey = (XMSSPrivateKey) privateKey;
        BCXMSSPublicKey xmssPublicKey = (BCXMSSPublicKey) publicKey;
        System.out.println("Key type, digest & length privateKey: " + privateKey.getAlgorithm() + " " + xmssPrivateKey.getTreeDigest() + " " + privateKey.getEncoded().length);
        System.out.println("Key type, digest & length publicKey:  " + publicKey.getAlgorithm() + " " + xmssPublicKey.getTreeDigest() + " "  + publicKey.getEncoded().length);
        System.out.println("Remaining usages for privateKey:      " + xmssPrivateKey.getUsagesRemaining());

        System.out.println("\nsign one message");
        byte[] messageToSign = "message to sign".getBytes("UTF-8");
        System.out.println("message length:                       " + messageToSign.length);
        Signature xmssSig = Signature.getInstance("XMSS", "BCPQC");
        xmssSig.initSign(privateKey);
        xmssSig.update(messageToSign, 0, messageToSign.length);
        byte[] signature = xmssSig.sign();
        System.out.println("signature length:                     " + signature.length);
        System.out.println("Remaining usages for privateKey:      " + xmssPrivateKey.getUsagesRemaining());

        System.out.println("\nverify the signature");
        xmssSig.initVerify(kp.getPublic());
        xmssSig.update(messageToSign, 0, messageToSign.length);
        System.out.println("XMSS signature  verified:             " + xmssSig.verify(signature));

        System.out.println("\nget a signatureKey for 5 usages");
        XMSSPrivateKey signatureKey = xmssPrivateKey.extractKeyShard(5);
        System.out.println("Remaining usages for privateKey:      " + xmssPrivateKey.getUsagesRemaining());
        System.out.println("Remaining usages for signatureKey:    " + signatureKey.getUsagesRemaining());

        System.out.println("\nsign until remaining usages = 0 [lasts a minute...]");
        long remainingUsages = xmssPrivateKey.getUsagesRemaining();
        for (int i = 0; i < remainingUsages; i++) {
            xmssSig.initSign(privateKey);
            xmssSig.update(messageToSign, 0, messageToSign.length);
            signature = xmssSig.sign();
        }
        System.out.println("Remaining usages for privateKey:      " + xmssPrivateKey.getUsagesRemaining());

        System.out.println("\none more signature raises an SignatureException");
        xmssSig.initSign(privateKey);
        xmssSig.update(messageToSign, 0, messageToSign.length);
        try {
        signature = xmssSig.sign(); } catch (SignatureException e) {
            System.err.println("Signature Exception: " + e);
        }
    }
}