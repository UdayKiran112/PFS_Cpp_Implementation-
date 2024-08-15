#include <bits/stdc++.h>
#include "TA.h"
using namespace std;

static bool signatureGeneration(octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A);
bool checkRegValid(octet *registrationId);

TA::TA() {}

TA::TA(csprng *RNG)
{
    // only groupKey should be initialized with Key constructor
    this->groupKey = Key(RNG);
}

void TA::validateRequest(octet *registrationId, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    auto regValid = checkRegValid(registrationId);
    if (!regValid)
    {
        cout << "Registration ID is not valid" << endl;
        return;
    }
    // add (registrationId, vehiclePublicKey) to the map
    auto dict = this->getDictionary();
    dict.push_back(make_pair(*registrationId, *vehiclePublicKey));
    this->setDictionary(dict);
    // generate signatureKey and A
    auto temp = this->getGroupKey().getPrivateKey();
    bool sigGen = signatureGeneration(&temp, vehiclePublicKey, SignatureKey, A);
}

void TA::setGroupKey(Key groupKey)
{
    this->groupKey = groupKey;
}

Key TA::getGroupKey()
{
    return groupKey;
}

vector<pair<octet, octet>> TA::getDictionary()
{
    return dictionary;
}

void TA::setDictionary(vector<pair<octet, octet>> dictionary)
{
    this->dictionary = dictionary;
}

bool checkRegValid(octet *registrationId)
{
    // TODO
    //  Check if registrationId is valid
    return true;
}

static bool signatureGeneration(octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;

    // Seed RNG
    time((time_t *)&ran);
    RAW.len = 100;
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i; // Consider using more randomness here
    CREATE_CSPRNG(&RNG, &RAW);

    // Generate a random key
    Key randomKey(&RNG);

    // Ensure 'result' is properly initialized to handle the concatenation
    octet result;
    result.len = 0; // Start with an empty octet
    result.max = vehiclePublicKey->len + randomKey.getPrivateKey().len;
    result.val = new char[result.max];

    // Concatenate vehicle public key and random private key
    auto temp = randomKey.getPrivateKey();
    Message::Concatenate_octet(vehiclePublicKey, &temp, &result);

    // Hash the concatenated result into SignatureKey
    Message::Hash_Function(&result, SignatureKey, 0);

    // Add the group private key to the hashed result
    Message::add_octets(groupPrivateKey, &result, SignatureKey);

    // Clean up
    delete[] result.val;

    return true;
}
