#include <bits/stdc++.h>
#include "Key.h"
#include "TA.h"
#include "Message.h"
using namespace std;

class Vehicle{
    private:
        int registrationId;
        Key vehicleKey;
        int signatureKey; // will change
        int A; //Public Key data Type
        const TA& ta;
        
    public:
        Vehicle(int registrationId, Key vehicleKey, int signatureKey, int A, const TA& ta);
        int getRegistrationId();
        Key getVehicleKey();
        int getSignatureKey();
        int getA();
        const TA& getTA();
        
        void setRegistrationId(int registrationId);
        void setVehicleKey(Key vehicleKey);
        void setSignatureKey(int signatureKey);
        void setA(int A);
        void setTA(const TA& ta);
        
        int generateSignatureKey(int randomGenerator);
        int generateA(int randomGenerator);
        int generateRegistrationId(int randomGenerator);
        Key generateVehicleKey(int randomGenerator);

        void requestVerification();
        
        void sendingMessage(int vehiclePrivateKey /*prolly BIG*/, int signatureKey /*prolly BIG*/, Message message);

        void validateMessage(Message message, int signatureKey /*prolly BIG*/, int A /*public key datatype*/, int senderPublicKey);
};