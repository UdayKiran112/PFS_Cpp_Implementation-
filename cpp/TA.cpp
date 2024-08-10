#include <bits/stdc++.h>
#include "TA.h"
using namespace std;

void TA::validateRequest(octet registrationId, octet vehiclePublicKey, octet SignatureKey, octet A){
    auto regValid = checkRegValid(registrationId);
    if(!regValid){
        cout << "Registration ID is not valid" << endl;
        return;
    }
    // add (registrationId, vehiclePublicKey) to the map
    auto dict = this->getDictionary();
    dict.push_back(make_pair(registrationId, vehiclePublicKey));
    this->setDictionary(dict);
    // generate signatureKey and A
    bool sigGen = signatureGeneration();
}

void TA::setGroupKey(Key groupKey){
    this->groupKey = groupKey;
}

Key TA::getGroupKey(){
    return groupKey;
}

vector<pair<octet, octet>> TA::getDictionary(){
    return dictionary;
}

void TA::setDictionary(vector<pair<octet, octet>> dictionary){
    this->dictionary = dictionary;
}

bool checkRegValid(octet registrationId){
    // Check if registrationId is valid
    return true;
}

static bool signatureGeneration(){
    return true;
}