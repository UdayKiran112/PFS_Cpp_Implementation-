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

