#include<bits/stdc++.h>
#include "Key.h"
using namespace std;
class TA{
    private:
        Key groupKey;
        vector<pair<octet, octet>> dictionary;
    
    public:
        TA();
        void validateRequest(octet registrationId, octet vehiclePublicKey, octet SignatureKey, octet A);
        void setGroupKey(Key groupKey);
        Key getGroupKey();
        vector<pair<octet, octet>> getDictionary();
        void setDictionary(vector<pair<octet, octet>> dictionary);
};