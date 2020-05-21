See https://stackoverflow.com/questions/61927913/bouncycastle-update-from-1-46-to-1-56-not-working for more details

The files RSAKeyPairGenerator.java, PGPExampleUtil.java and KeyBasedLargeFileProcessor.java were taken from 
Bouncy Castle Version 1.65 examples:

https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/

In 'KeyBasedLargeFileProcessor' I modified the constructor of the methods decryptFile and encryptFile from 
'private' to 'public' to get access from new PGPMain.java.

