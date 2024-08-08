#include<bits/stdc++.h>
#include "Key.h"
using namespace std;
class TA{
    private:
        Key groupKey;
        unordered_map<int, int> dictionary;
    
    public:
        void validateRequest(int registrationId, int vehiclePublicKey, int SignatureKey /*need to set*/, int A /*need to set*/);
        void setGroupKey(Key groupKey);
        Key getGroupKey();
};