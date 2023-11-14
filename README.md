# Digital Green Certificate Generator

Just for fun. No fraud intended

### Important note

I also got no valid signature (private key). All of which has been randomly generated.

### Fork reason

I have included the cbor tag "18", which is present in real covid certificates and I replace the cose encryption with these classes:
cose.algorithm.Es256
cose.keys.EC2key
cose.keys.curves.P256
