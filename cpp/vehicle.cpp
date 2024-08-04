#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/ecp_Ed25519.h"
using namespace std;
using namespace B256_56;

vehicle::vehicle(int rId, Point generator){
    this->rId = rId;
    this->vehiclePrivateKey = privateKeyGeneration(generator);
    this->vehiclePublicKey = publicKeyGeneration();
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

long long vehicle::getVehiclePublicKey() const {
    return vehiclePublicKey;
}

void vehicle::setVehiclePublicKey(Point publicKey) {
    this->vehiclePublicKey = publicKey;
}

long long vehicle::getSignature() const {
    return signature;
}

void vehicle::setSignature(long long signature){
    this->signature = signature;
}

long long vehicle::privateKeyGeneration(Point generator){
    /**TODO: **/
    return 0;
}

long long vehicle::publicKeyGeneration(){
    /**TODO: **/
    return 0;
}

void vehicle::requestVerification(const BIG rId, long long publicKey){
    /**TODO: **/
    vehicle::setSignature();
}