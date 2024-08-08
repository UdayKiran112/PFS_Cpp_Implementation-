#include <bits/stdc++.h>
#include "TA.h"
using namespace std;

TA::TA(){
    
}

void TA::validateRequest(int registrationId, int vehiclePublicKey, int SignatureKey /*need to set*/, int A /*need to set*/){
    //TODO
}

void TA::setGroupKey(Key groupKey){
    this->groupKey = groupKey;
}

Key TA::getGroupKey(){
    return groupKey;
}