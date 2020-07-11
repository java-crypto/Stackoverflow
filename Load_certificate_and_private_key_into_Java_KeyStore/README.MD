All files in this folder are for this question on stackoverflow:
https://stackoverflow.com/questions/62701407/load-certificate-and-private-key-into-java-keystore

Load certificate and private key into Java KeyStore

It sounds to me that the import is a "one time job" and do not need to get solved programmatically.
I recommend you use the KeystoreExplorer for this job - it worked perfectly in my testcase:

Here are my steps to do the import, all files are available in my GitHub-Repo (https://github.com/java-crypto/Stackoverflow/tree/master/Load_certificate_and_private_key_into_Java_KeyStore):

1) create the private key + certificate file with open ssl:

openssl req -x509 -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem

This will create the 2 files key.pem (encrypted private key) and cert.pem (certificate with public key). I used some sample data
and the password for key.pem is 123456.

<b>The key and certificate are sample data !</b>

2) download the Keystore Explorer from https://keystore-explorer.org/downloads.html

3) run explorer and create a new KeyStore

4) select KeyStore type = PKCS12

5) Import KeyPair with "Tools" - "Import Key Pair"

6) Select Key Pair Type as PKCS #8

7) Set the password (123456) and choose the key- and cert-file and press "Import"

8) Choose the alias for the key (default is the given email in the certificate

9) Set a Key Pair Entry password: kpe123456

10) Message: Key Pair Import successful

11) save your new keystore with "File" - "Save as"

12) Set a password for the Key Store: ks123456

13) choose path + filename: keystore.p12

14) ready - your private and certificate are imported in the new created Key Store keystore.p12
