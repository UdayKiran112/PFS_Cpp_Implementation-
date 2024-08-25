#include <bits/stdc++.h>
#include "Lib/core.h"
#include "Vehicle.h"
#include "Message.h"
using namespace std;

// using namespace core;

char *StrtoCharstar(string s)
{
    char *c = new char[s.length() + 1];
    strcpy(c, s.c_str());
    return c;
}

void sendAndValidate()
{
}

int main()
{

    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;
    time((time_t *)&ran);
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i;
    CREATE_CSPRNG(&RNG, &RAW);

    // octet privateKey;
    Ed25519::ECP generator;
    Key::PointGeneration(&generator);

    Vehicle vehicle = Vehicle(&RNG);

    // vehicle.requestVerification(&RNG);

    // Message message;
    string msg = "Mugiwara";
    chrono::system_clock::time_point TS = chrono::system_clock::now();
    Key Bkey(&RNG);
    octet b = Bkey.getPrivateKey();
    octet B = Bkey.getPublicKey();

    Message message(msg, TS, B);
}