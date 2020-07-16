These files are testfiles for my question on https://stackoverflow.com/questions/61520639/chacha20-poly1305-fails-with-shortbufferexception-output-buffer-too-small

As of date of asking my question (April 30th 2020) the class ChaCha20Poly1305Jce is throwing an error due to an
OpenJava11-issue.

Update 17.07.2020: Using OpenJDK 11.0.8 Early Access the slightly edited "ChaCha20Poly1305JceCis.java" is running:

java version: 11.0.8-ea+8
start encryption
keySpec: ChaCha20 RAW
cipher algorithm: ChaCha20-Poly1305/None/NoPadding
start decryption
compare plain <-> dec: true
