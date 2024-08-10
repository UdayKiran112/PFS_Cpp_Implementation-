#include <bits/stdc++.h>
#include "Key.h"
using namespace std;
Key::Key()
{
}
Key::Key(int privateKey)
{
}
int Key::getPrivateKey()
{
}
int Key::getPublicKey()
{
}
void Key::setPrivateKey(int privateKey)
{
}
void Key::setPublicKey(int publicKey)
{
}

/**
 * Generates a point on the Ed25519 curve and assigns it to the given ECP object.
 *
 * @param G the ECP object to store the generated point
 *
 * @throws None
 */
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

/**
 * Generates a private key using a random number generator.
 *
 * @param randomNumberGenerator Pointer to a csprng object for generating random numbers. If nullptr, uses the bytes in secretKey to generate the secret.
 * @param secretKey Pointer to an octet object to store the generated secret key.
 *
 * @return 0 if the secret key is in range of the group order, -1 otherwise.
 *
 * @throws None
 */
int Key::generatePrivateKey(csprng *randomNumberGenerator, octet *secretKey)
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
        BIG_fromBytes(secret, secretKey->val);
    }

    secretKey->len = NLEN_B256_56;
    BIG_toBytes(secretKey->val, secret);

    // Ensure that secretKey is in range of group order
    if (ECP_IN_RANGE(secretKey) == 0)
    {
        return -1;
    }
    return 0;
}

/**
 * Generates a public key from a secret key and a generator point on an elliptic curve.
 *
 * @param secretKey Pointer to an octet object containing the secret key.
 * @param publicKey Pointer to an octet object to store the generated public key.
 * @param generatorPoint Pointer to an ECP object representing the generator point on the elliptic curve.
 *
 * @return 0 if the public key is successfully generated and validated, -1 otherwise.
 *
 * @throws None.
 */
int Key::generatePublicKey(octet *secretKey, octet *publicKey, Ed25519::ECP *generatorPoint)
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

    BIG_fromBytes(secret, secretKey->val);
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
    BIG_toBytes(output->val, x);   // Convert the BIG number back to bytes

    cout << "Hashed" << endl;
}
