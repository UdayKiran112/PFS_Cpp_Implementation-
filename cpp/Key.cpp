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

    if (randomNumberGenerator != nullptr)
    {
        BIG_random(secret, randomNumberGenerator);
    }
    else
    {
        BIG_fromBytes(secret, PrivateKey->val);
    }

    PrivateKey->len = NLEN_B256_56;
    BIG_toBytes(PrivateKey->val, secret);

    // Ensure that PrivateKey is in range of group order
    if (ECP_IN_RANGE(PrivateKey) == 0)
    {
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
    int res = Ed25519::ECP_PUBLIC_KEY_VALIDATE(publicKey);
    if (res != 0)
    {
        cout << " ECP Public Key Validation Failed " << endl;
        return -1;
    }
    return res;
}

void Hash_Function(octet *input, octet *output, int pad)
{
    using namespace core;
    using namespace Ed25519;
    using namespace B256_56;
    using namespace F25519;
    /* The 'n' argument is unused in this function. It is likely that it was included as a placeholder for a future
       modification that would involve a third parameter. The 'n' value is not used in any of the cases of the switch
       statement. The 'n' value is instead used in the default case, which is an empty case and therefore does not
       have any effect on the function.

       Therefore, the 'n' argument can be safely removed from the function signature without affecting the behavior
       of the code. */
    int n = -1;
    GPhash(SHA256, 32, output, 32, pad, input, n, NULL);

    // Map octet hash to Zp*
    BIG x, prime;
    BIG_fromBytes(x, output->val); // Convert hash bytes to BIG number
    BIG_zero(prime);               // Initialize BIG 'prime' to zero
    BIG_rcopy(prime, Modulus);     // Copy the constant Modulus value to 'prime'
    BIG_mod(x, prime);             // Take x mod prime
    output->len = 32;
    output->max = 32;
    output->val = new char[32];
    BIG_toBytes(output->val, x);   // Convert the BIG number back to bytes
    
    cout << "Hashed" << endl;
}

/* Concatenate two octet strings */
void Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;
    result->len = total_length;
    memcpy(result->val, data1->val, data1->len);
    memcpy(result->val + data1->len, data2->val, data2->len);
}

// Concatenate two BIG numbers
void concatenate_values(B256_56::BIG point1, B256_56::BIG point2, octet *result)
{
    using namespace B256_56;
    octet p1, p2;
    p1.len = NLEN_B256_56;
    p2.len = NLEN_B256_56;

    BIG_toBytes(p1.val, point1);
    BIG_toBytes(p2.val, point2);
    Concatenate_octet(&p1, &p2, result);
    cout << "Concatenated" << endl;
}