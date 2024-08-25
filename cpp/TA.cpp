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

void TA::validateRequest(csprng* RNG, octet *registrationId, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
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
    bool sigGen = signatureGeneration(RNG, &temp, vehiclePublicKey, SignatureKey, A);
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

static bool signatureGeneration(csprng* RNG, octet *groupPrivateKey, octet *vehiclePublicKey, octet *SignatureKey, octet *A)
{
    // Generate a random key
    Key randomKey(RNG);

    
    // Ensure 'result' is properly initialized to handle the concatenation
    octet result;
    result.len = 0; // Start with an empty octet
    result.max = vehiclePublicKey->len + randomKey.getPrivateKey().len;
    result.val = new char[result.max];

    // Concatenate vehicle public key and random private key
    auto publicKey = randomKey.getPublicKey();
    OCT_copy(A,&publicKey);
    Message::Concatenate_octet(vehiclePublicKey, &publicKey, &result);

    // Hash the concatenated result into a temporary hash result
    octet hashResult;
    hashResult.len = 0;
    hashResult.max = 32; // Replace with the actual hash size
    hashResult.val = new char[hashResult.max];
    Message::Hash_Function(&result, &hashResult, 0);

    // Multiply the random private key by the hash result
    auto privateKey = randomKey.getPrivateKey();
    octet product;
    product.len = 0;
    product.max = privateKey.len;  // Assuming result fits into the size of the private key
    product.val = new char[product.max];
    Message::multiply_octet(&privateKey, &hashResult, &product);

    // Add the group private key to the multiplication result
    Message::add_octets(groupPrivateKey, &product, SignatureKey);

    // Clean up
    delete[] result.val;
    delete[] hashResult.val;
    delete[] product.val;

    return true;
}
    