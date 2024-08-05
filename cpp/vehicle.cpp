#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/ecp_Ed25519.h"
#include "vehicle.h"
#include "key.h"
using namespace std;
using namespace B256_56;

vehicle::vehicle(int rId, Point generator){
    key aKey = key();
    this->rId = rId;
    this->vehiclePrivateKey = aKey.privateKeyGeneration(generator);
    this->vehiclePublicKey = aKey.publicKeyGeneration(this->vehiclePrivateKey);
}

vehicle::~vehicle(){
}

int vehicle::getRId() const {
    return rId;
}

void vehicle::setRId(int rId) {
    this->rId = rId;
}

long long vehicle::getVehiclePrivateKey() const {
    return vehiclePrivateKey;
}

void vehicle::setVehiclePrivateKey(long long privateKey) {
    this->vehiclePrivateKey = privateKey;
}

Point vehicle::getVehiclePublicKey() const {
    return vehiclePublicKey;
}

void vehicle::setVehiclePublicKey(Point publicKey) {
    this->vehiclePublicKey = publicKey;
}

Point vehicle::getSignature() const {
    return signature;
}

void vehicle::setSignature(Point signature){
    this->signature = signature;
}

void vehicle::requestVerification(const BIG rId, long long publicKey){
    /**TODO: **/
    Point x;
    vehicle::setSignature(x);
}