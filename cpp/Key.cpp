#include <bits/stdc++.h>
#include "Key.h"
using namespace std;
Key::Key()
{
}
Key::Key(octet privateKey){
    this->privateKey = privateKey;
}
octet Key::getPrivateKey(){
    return privateKey;
}
octet Key::getPublicKey(){
    return publicKey;
}
void Key::setPrivateKey(octet privateKey){
    this->privateKey = privateKey;
}
void Key::setPublicKey(octet publicKey){
    this->publicKey = publicKey;
}

void Key::PointGeneration(Ed25519::ECP G)
{
    using namespace Ed25519;

    ECP P;
    ECP_generator(&P);
    if (ECP_isinf(&P) == 1)
    {
        cout << "Point at infinity" << endl;
        exit(0);
    }
    else
    {
        ECP_copy(&G, &P);
        cout << "Point generated" << endl;
        ECP_output(&G);
    }
}

int Key::generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey)
{
    using namespace Ed25519;
    using namespace B256_56;

    BIG order;
    // Manually copy the contents of CURVE_Order into the local order variable
    for (int i = 0; i < NLEN_B256_56; i++)
    {
        order[i] = CURVE_Order[i];
    }

    BIG secret;

    int err = 0;
    if (randomNumberGenerator != nullptr)
    {
        BIG_random(secret, randomNumberGenerator);
    }
    else
    {
        BIG_fromBytes(secret, PrivateKey->val);
    }

    if (err != 0)
    PrivateKey->len = NLEN_B256_56;
    BIG_toBytes(PrivateKey->val, secret);

    // Ensure that PrivateKey is in range of group order
    if (ECP_IN_RANGE(PrivateKey) == 0)
    {
        return err;
        return -1;
    }
    return 0;
}

int Key::generatePublicKey(octet *PrivateKey, octet *publicKey, Ed25519::ECP *generatorPoint)
{
    using namespace Ed25519;
    using namespace B256_56;
    int res = 0;
    BIG secret, order;

    // Manually copy the contents of CURVE_Order into the local order variable
    for (int i = 0; i < NLEN_B256_56; i++)
    {
        order[i] = CURVE_Order[i];
    }

    BIG_fromBytes(secret, PrivateKey->val);
    ECP_mul(generatorPoint, secret);
    ECP_toOctet(publicKey, generatorPoint, false);

    // Validating Public Key
    res = Ed25519::ECP_PUBLIC_KEY_VALIDATE(publicKey);
    if (res != 0)
    {
        cout << " ECP Public Key Validation Failed " << endl;
        return -1;
    }
    return res;
}