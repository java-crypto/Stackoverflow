The cert-files in this folder are sample files produced for

https://stackoverflow.com/questions/62890604/decoding-from-java-to-powershell

The cert32.enc file is encrypted with AES ECB PKCS5Padding using a 16 byte key:
(base64 encoding): MTIzNDU2Nzg5MDEyMzQ1Ng==

The cert64.enc file is encrypted with AES ECB PKCS5Padding using a 32 byte key:
(base64 encoding): MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

They will decrypt to the file cert.pem

for decryption use openssl (command line) after decoding the base64-key to a hexstring (e.g. use https://base64.guru/converter/decode/hex):

openssl enc -aes-128-ecb -d -in cert32.enc -out cert.pem -K "31323334353637383930313233343536"

openssl enc -aes-256-ecb -d -in cert64.enc -out cert.pem -K "3132333435363738393031323334353637383930313233343536373839303132"
