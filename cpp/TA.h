#include<bits/stdc++.h>
#include "Key.h"
#include "Message.h"
using namespace std;
class TA{
    private:
        Key groupKey;
        vector<pair<octet, octet>> dictionary;
    
    public:
        TA();
        TA(csprng *RNG);
        void validateRequest(octet *registrationId, octet *vehiclePublicKey, octet *SignatureKey, octet *A);
        void setGroupKey(Key groupKey);
        Key getGroupKey();
        vector<pair<octet, octet>> getDictionary();
        void setDictionary(vector<pair<octet, octet>> dictionary);
};