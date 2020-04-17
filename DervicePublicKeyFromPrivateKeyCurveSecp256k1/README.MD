This is the final solution regarding my post on stackoverflow:

https://stackoverflow.com/questions/61069182/derive-ec-public-key-from-private-key-string-in-native-java-for-curve-secp256k1

It shows the Public Key derivation from a (uncompressed) Private Key for Curve secp256k1 which is used for
Bitcoin operations.

One solution is to use bouncy castle as provider (very short solution but needs an external library) or do the native Java way with scalar operations.

The scalar operations got written by the author: SkateScout and were published here:
https://stackoverflow.com/a/42797410/8166854
 
As per comment from user President James Moveon Polk there was a small error in method "scalmult" that was corrected.

For converting the private key string to the corresponding public key you need a "magic" header string that is specific 
for the used curve (secp256k1). You can get this string for other curves with class CreateHeadForNamedCurveSo.java.

Enjoy !
