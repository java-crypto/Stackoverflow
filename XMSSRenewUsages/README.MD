These files are testfiles for my question on https://stackoverflow.com/questions/61595184/xmss-renewing-of-remaining-usages-of-private-keys-possible

The full example shows how to generate a XMSS keypair and the signature & verfication steps. With each signature (and getting subkeys via extractKeyShard) the "remaining usages" counter decreases down to 0 and then no more signatures are available with this private key.

My question: is there any way to "renew" the usages of the private key so that the public key verifies the "renewed" as well ? Of course I can simply generate a new keypair or use a changed parameter in keypair generation ('16' or '20' instead of '10') but this only extends the time until remaining goes to 0.  
