#include <bits/stdc++.h>
#include "Key.h"
#include "TA.h"
#include "Message.h"

#include "Lib/core.h"
#include "Lib/eddsa_Ed25519.h"

using namespace std;

class Vehicle
{
private:
    octet registrationId;
    Key vehicleKey;
    octet signatureKey; // will change
    octet A;            // Public Key data Type
    TA ta;

public:
    Vehicle(octet registrationId, Key vehicleKey, octet signatureKey, octet A, TA ta);
    Vehicle(csprng *RNG);
    Vehicle();
    octet getRegistrationId();
    Key getVehicleKey();
    octet getSignatureKey();
    octet getA();
    TA getTA();

    void setRegistrationId(octet registrationId);
    void setVehicleKey(Key vehicleKey);
    void setSignatureKey(octet signatureKey);
    void setA(octet A);
    void setTA(TA ta);

    void requestVerification();

    void sendingMessage(core::octet vehiclePrivateKey, core::octet signatureKey, Message message);

    void validateMessage(Message message, octet signatureKey, octet A, octet senderPublicKey);
};