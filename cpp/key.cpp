#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/core.h"
#include "Lib/ecp_Ed25519.h"
#include "Lib/randapi.h"
#include "Lib/big_B256_56.h"
#include "key.h"
using namespace B256_56;
using namespace std;



int Priv_Key_Gen(csprng *randomNumberGenerator, octet *secretKey)
{
    using namespace Ed25519;
    ECP generator;
    ECP_generator(&generator);
    if (ECP_generator(&generator) == 0)
    {
        cout << "Point at infinity" << endl;
        return -1;
    }
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

int main()
{
    csprng RNG;
    int i;
    char pr[10];
    unsigned long ran;
    char raw[100];

    // Seed RNG with some randomness
    time((time_t *)&ran);
    for (i = 0; i < 100; i++)
    {
        raw[i] = i ^ ran;
    }

    RAND_seed(&RNG, 100, raw);

     char sk_val[MODBYTES_B256_56];
    octet SK = {0, sizeof(sk_val), sk_val};

    char sk2_val[MODBYTES_B256_56];
    octet SK2 = {0, sizeof(sk2_val), sk2_val};

    if (Priv_Key_Gen(&RNG, &SK) != 0)
    {
        cout << "Error" << endl;
        return -1;
    }
    if (Priv_Key_Gen(&RNG, &SK2) != 0)
    {
        cout << "Error" << endl;
        return -1;
    }

    return 0;
}
