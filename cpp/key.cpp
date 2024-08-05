#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/ecp_Ed25519.h"
#include "Lib/randapi.h"
#include "Lib/big_B256_56.h"
#include "key.h"
#include"point.h"
using namespace B256_56;
using namespace Ed25519;
using namespace std;



int Priv_Key_Gen(csprng *randomNumberGenerator, octet *secretKey,ECP *generatorPoint)
{
    Point::Point_Generation(*generatorPoint);
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

    // Ensure that secret is within range [1,order-1]
    if (BIG_comp(secret, order) >= 0)
    {
        return -1;
    }
    return 0;
}

int Pub_Key_Gen(octet *secretKey, octet *publicKey)
{
    // TODO
    BIG order;
}

