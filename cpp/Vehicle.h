#include <bits/stdc++.h>
#include "Key.h"
#include "TA.h"
#include "Message.h"

#include "Lib/core.h"
#include "Lib/eddsa_Ed25519.h"

using namespace std;

class Vehicle{
    private:
        int registrationId;
        Key vehicleKey;
        int signatureKey; // will change
        int A; //Public Key data Type
        TA ta;
        
    public:
        Vehicle(int registrationId, Key vehicleKey, int signatureKey, int A, TA ta);
        Vehicle();
        int getRegistrationId();
        Key getVehicleKey();
        int getSignatureKey();
        int getA();
        TA getTA();
        
        void setRegistrationId(int registrationId);
        void setVehicleKey(Key vehicleKey);
        void setSignatureKey(int signatureKey);
        void setA(int A);
        void setTA(TA ta);
        
        int generateSignatureKey(int randomGenerator);
        int generateA(int randomGenerator);
        int generateRegistrationId(int randomGenerator);
        Key generateVehicleKey(int randomGenerator);

        void requestVerification();
        
        void sendingMessage(int vehiclePrivateKey /*prolly BIG*/, int signatureKey /*prolly BIG*/, Message message);

        void validateMessage(Message message, int signatureKey /*prolly BIG*/, int A /*public key datatype*/, int senderPublicKey);
};