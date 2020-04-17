import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class CreateHeadForNamedCurveSo {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        System.out.println("create private key head for named curve");
        System.out.println("see https://stackoverflow.com/a/30471945/8166854");
        System.out.println("author: Maarten Bodewes\n");
        // input
        String curvename = "secp256k1";
        String privateKeyHeaderExpected = "303E020100301006072A8648CE3D020106052B8104000A042730250201010420";
        String privateKeyHeaderFromCurve = createPrivateKeyHeaderForNamedCurve(curvename);
        // output
        System.out.println("Curvename                    : " + curvename);
        System.out.println("expected private key header  : " + privateKeyHeaderExpected);
        System.out.println("calculated private key header: " + privateKeyHeaderFromCurve);
        System.out.println("private key headers matching : " + privateKeyHeaderExpected.contentEquals(privateKeyHeaderFromCurve));
    }

    private static String createPrivateKeyHeaderForNamedCurve(String name)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec m = new ECGenParameterSpec(name);
        kpg.initialize(m);
        ECPrivateKey privateKey = (ECPrivateKey) kpg.generateKeyPair().getPrivate();
        PKCS8EncodedKeySpec pKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        String pKCS8EncodedKeySpecString = byteArrayToHexString(pKCS8EncodedKeySpec.getEncoded());
        return pKCS8EncodedKeySpecString.substring(0,64);
    }

    private static String byteArrayToHexString(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02X", b));
        return sb.toString();
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
