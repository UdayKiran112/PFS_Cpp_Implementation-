#include <bits/stdc++.h>
#include "Lib/arch.h"
#include "Lib/ecp_Ed25519.h"
#include "vehicle.h"
#include "key.h"
#include "Lib/eddsa_Ed25519.h"
#include <chrono>
using namespace std;
using namespace B256_56;
using namespace Ed25519;

// Define T_replay as a global variable (e.g., 1000 milliseconds or 1 second)
const long long T_replay = 1000; // Duration in milliseconds

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

/**
 * Signs a message using the Ed25519 signature scheme.
 *
 * @param ph A boolean indicating whether the pre-hashed version of the signature is used.
 * @param secretKey A pointer to the octet array containing the secret key.
 * @param context A pointer to the octet array containing the context.
 * @param message A pointer to the octet array containing the message.
 * @param signature A pointer to the octet array where the signature will be stored.
 *
 * @return A boolean indicating whether the signature was successfully generated.
 *
 * @throws None.
 */
bool signMessage(bool ph,octet *secretKey, octet *context, octet *message, octet *signature){
    using namespace Ed25519;
    return EDDSA_SIGNATURE(ph,secretKey,context,message,signature);
}

bool verifyMessage(bool ph,octet *publicKey, octet *context, octet *message, octet *signature){
    using namespace Ed25519;
    return EDDSA_VERIFY(ph,publicKey,context,message,signature);
}

bool Validate_Message(octet* message, octet* message_signature, octet* vehicle_public_key,octet* General_Key,ECP *A,ECP *B, ECP *G,chrono::system_clock::time_point timeStamp){
    auto now = std::chrono::system_clock::now(); 
    if (chrono::duration_cast<chrono::milliseconds>(now - timeStamp).count() > T_replay){
        return false;
    }
    return verifyMessage(false,vehicle_public_key,NULL,message,message_signature);
}