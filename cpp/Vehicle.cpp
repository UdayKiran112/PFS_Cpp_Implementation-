#include <bits/stdc++.h>
#include "Vehicle.h"
using namespace std;

Vehicle::Vehicle(int registrationId, Key vehicleKey, int signatureKey, int A, TA ta){
    this->registrationId = registrationId;
    this->vehicleKey = vehicleKey;
    this->signatureKey = signatureKey;
    this->A = A;
    this->ta = ta;
}

int Vehicle::getRegistrationId(){
    return registrationId;
}

Key Vehicle::getVehicleKey(){
    return vehicleKey;
}

int Vehicle::getSignatureKey(){
    return signatureKey;
}

int Vehicle::getA(){
    return A;
}

TA Vehicle::getTA(){
    return ta;
}

void Vehicle::setRegistrationId(int registrationId){
    this->registrationId = registrationId;
}

void Vehicle::setVehicleKey(Key vehicleKey){
    this->vehicleKey = vehicleKey;
}

void Vehicle::setSignatureKey(int signatureKey){
    this->signatureKey = signatureKey;
}

void Vehicle::setA(int A){
    this->A = A;
}

void Vehicle::setTA(TA ta){
    this->ta = ta;
}

int Vehicle::generateSignatureKey(int randomGenerator){
    return 0;
}

int Vehicle::generateA(int randomGenerator){
    return 0;
}

int Vehicle::generateRegistrationId(int randomGenerator){
    return 0;
}

Key Vehicle::generateVehicleKey(int randomGenerator){
    return Key();
}

void Vehicle::requestVerification(){
    //TODO
}

void Vehicle::sendingMessage(int vehiclePrivateKey /*prolly BIG*/, int signatureKey /*prolly BIG*/, Message message){
    //TODO
}

void Vehicle::validateMessage(Message message, int signatureKey /*prolly BIG*/, int A /*public key datatype*/, int senderPublicKey){
    //TODO
}

/**
     * Signs a message using the Ed25519 algorithm.
     *
     * @param ph a boolean indicating whether to include the prehash flag
     * @param secretKey the secret key for signing the message
     * @param context additional context for the message
     * @param message the message to be signed
     * @param signature the resulting signature
     *
     * @return true if the message is successfully signed, false otherwise
     *
     * @throws None
 */
bool signMessage(bool ph,octet *secretKey, octet *context, octet *message, octet *signature){
    using namespace Ed25519;
    return EDDSA_SIGNATURE(ph,secretKey,context,message,signature);
}

/**
 * Verifies a message using the Ed25519 algorithm.
 *
 * @param ph a boolean indicating whether to include the prehash flag
 * @param publicKey the public key for verification
 * @param context additional context for the message
 * @param message the message to be verified
 * @param signature the signature to verify the message
 *
 * @return true if the message is successfully verified, false otherwise
 *
 * @throws None
 */
bool verifyMessage(bool ph,octet *publicKey, octet *context, octet *message, octet *signature){
    using namespace Ed25519;
    return EDDSA_VERIFY(ph,publicKey,context,message,signature);
}

bool Validate_Message(octet* message, octet* message_signature, octet* vehicle_public_key,octet* General_Key,ECP *A,ECP *B, ECP *G,chrono::system_clock::time_point timeStamp){
    auto now = std::chrono::system_clock::now(); 
    if (chrono::duration_cast<chrono::milliseconds>(now - timeStamp).count() > T_replay){
        return false;
    }
    // Function has to be edited still
    return true;
}

