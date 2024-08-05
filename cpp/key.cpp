#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/ecp_Ed25519.h"
#include "Lib/randapi.h"
#include "Lib/big_B256_56.h"
#include "Lib/ecdh_Ed25519.h"
#include "key.h"
#include "point.h"
using namespace B256_56;
using namespace Ed25519;
using namespace std;

int Priv_Key_Gen(csprng *randomNumberGenerator, octet *secretKey)
{
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

int Pub_Key_Gen(octet *secretKey, octet *publicKey, ECP *generatorPoint)
{
    int res = 0;
    BIG secret, order;

    // Manually copy the contents of CURVE_Order into the local order variable
    for (int i = 0; i < NLEN_B256_56; i++)
    {
        order[i] = CURVE_Order[i];
    }

    BIG_fromBytes(secret, secretKey->val);
    ECP_clmul(generatorPoint, secret, order);
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
