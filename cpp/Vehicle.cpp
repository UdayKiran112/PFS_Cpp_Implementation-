#include <bits/stdc++.h>
#include <chrono>
#include "Vehicle.h"
using namespace std;

bool signMessage(bool ph, octet *privateKey, octet *context, octet *message, octet *signature);

Vehicle::Vehicle(octet registrationId, Key vehicleKey, octet signatureKey, octet A, TA ta)
{
    this->registrationId = registrationId;
    this->vehicleKey = vehicleKey;
    this->signatureKey = signatureKey;
    this->A = A;
    this->ta = ta;
}

Vehicle::Vehicle(){}

Vehicle::Vehicle(csprng *RNG){
    //only ta should be initilized with TA constructor
    this->ta = TA(RNG);
}
octet Vehicle::getRegistrationId()
{
    return registrationId;
}

Key Vehicle::getVehicleKey()
{
    return vehicleKey;
}

octet Vehicle::getSignatureKey()
{
    return signatureKey;
}

octet Vehicle::getA()
{
    return A;
}

TA Vehicle::getTA()
{
    return ta;
}

void Vehicle::setRegistrationId(octet registrationId)
{
    this->registrationId = registrationId;
}

void Vehicle::setVehicleKey(Key vehicleKey)
{
    this->vehicleKey = vehicleKey;
}

void Vehicle::setSignatureKey(octet signatureKey)
{
    this->signatureKey = signatureKey;
}

void Vehicle::setA(octet A)
{
    this->A = A;
}

void Vehicle::setTA(TA ta)
{
    this->ta = ta;
}

using namespace core;
using namespace Ed25519;
void Vehicle::requestVerification() {
    octet signkey, virpubkey;

    // Store the result in a local variable first
    octet publicKey = this->getVehicleKey().getPublicKey();

    // Now you can safely take the address of the local variable
    this->ta.validateRequest(&(this->registrationId), &publicKey, &signkey, &virpubkey);
    
    this->setSignatureKey(signkey);
    this->setA(virpubkey);
}


static char *StrtoCharstar(string s)
{
    char *c = new char[s.length() + 1];
    strcpy(c, s.c_str());
    return c;
}

void Vehicle::sendingMessage(core::octet vehiclePrivateKey, core::octet signatureKey, Message message){
    char q[EFS_Ed25519], sig[2 * EFS_Ed25519];
    string s = message.getMessage();

    // Convert the string message to a char array
    char *msg = StrtoCharstar(s); // Ensure this allocates memory correctly
    if (!msg) {
        cout << "Failed to convert message to char*";
        return;
    }

    // Initialize octet structures
    octet D = {sizeof(int), sizeof(int), reinterpret_cast<char*>(&vehiclePrivateKey)};
    octet Q = {sizeof(q), sizeof(q), q};
    octet M = {static_cast<int>(s.length()), static_cast<int>(s.length()), msg};
    octet SIG = {sizeof(sig), sizeof(sig), sig};

    // Sign the message
    bool x = signMessage(false, &D, nullptr, &M, &SIG);
    if(!x) {
        cout << "No Signature Generated";
        delete[] msg; // Clean up memory if necessary
        return;
    }

    // Output the signature
    cout << "Signature= 0x";
    OCT_output(&SIG);

    // Clean up memory if necessary
    delete[] msg;
}

// Irrevelant function code unnecessarily

// void Vehicle::validateMessage(Message message, int signatureKey /*prolly BIG*/, int A /*public key datatype*/, int senderPublicKey)
// {
//     // TODO

//     auto timestamp = message.getTimestamp();
//     if (!Validate_Message(timestamp))
//     {
//         cout << "Message has Expired\n";
//         return;
//     }

//     octet Q,M, SIG;

//     string s = message.getMessage();
//     char *msg = StrtoCharstar(s);
//     if (!msg) {
//         cout << "Failed to convert message to char*";
//         return;
//     }
//     Q = {};
//     M = {static_cast<int>(s.length()), static_cast<int>(s.length()), msg};
//     SIG = {sizeof(signatureKey), sizeof(signatureKey), reinterpret_cast<char*>(&signatureKey)};

//     bool verify = verifyMessage(false, &Q, NULL, &M, &SIG);

//     if(!verify) {
//         cout << "Message has been Comprimised\n";
//         delete[] msg;
//     }
// }

/**
 * Signs a message using the Ed25519 algorithm.
 *
 * @param ph a boolean indicating whether to include the prehash flag
 * @param privateKey the secret key for signing the message
 * @param context additional context for the message
 * @param message the message to be signed
 * @param signature the resulting signature
 *
 * @return true if the message is successfully signed, false otherwise
 *
 * @throws None
 */
bool signMessage(bool ph, octet *privateKey, octet *context, octet *message, octet *signature)
{
    using namespace Ed25519;
    return EDDSA_SIGNATURE(ph, privateKey, context, message, signature);
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
static bool verifyMessage(bool ph, octet *publicKey, octet *context, octet *message, octet *signature)
{

    return EDDSA_VERIFY(ph, publicKey, context, message, signature);
}

#define T_replay 1000 // Define T_replay with an appropriate value

bool Vehicle::Validate_Message(Ed25519::ECP* GeneratorPoint, octet* signedMessage, Ed25519::ECP* PublicKey, Ed25519::ECP* VehiclePublicKey, Ed25519::ECP* B, Ed25519::ECP* A, chrono::system_clock::time_point timeStamp, octet* Message)
{
    using namespace B256_56;
    auto now = chrono::system_clock::now();
    if (chrono::duration_cast<chrono::milliseconds>(now - timeStamp).count() > T_replay) {
        return false;
    }

    // Initialize ECP variables
    ECP LHS, RHS, P, Apoint, Bpoint, PubKey, VehPubKey;
    // Copy values into other points to avoid issues with pointers
    ECP_copy(&P, GeneratorPoint);
    ECP_copy(&PubKey, PublicKey);
    ECP_copy(&VehPubKey, VehiclePublicKey);
    ECP_copy(&Apoint, A);
    ECP_copy(&Bpoint, B);

    // Compute LHS
    BIG signedMessageHash;
    BIG_fromBytes(signedMessageHash, signedMessage->val);
    ECP_mul(&P, signedMessageHash);
    ECP_copy(&LHS, &P);

    // Compute RHS partially -> GK + PKi
    ECP_copy(&RHS, PublicKey);
    ECP_add(&RHS, VehiclePublicKey);

    // Apoint calculation->A*H(PKi || A)
    ECP_add(VehiclePublicKey, A);
    octet A_hash_octet;
    ECP_toOctet(&A_hash_octet, VehiclePublicKey, true);
    octet Hash_A_out;
    Message::Hash_Function(&A_hash_octet, &Hash_A_out, 0);
    BIG A_hash;
    BIG_fromBytes(A_hash, A_hash_octet.val);
    ECP_mul(A, A_hash);

    // Bpoint calculation -> B*H(M|| T || B)
    ECP_copy(&Bpoint, B);
    octet result, B_octet, B_hash_octet;
    ECP_toOctet(&B_octet, &Bpoint, true);
    Message::Concatenate_octet(Message, &B_octet, &result);
    octet timestamp_oct;
    Message::timestamp_to_octet(timeStamp, &timestamp_oct);
    Message::Concatenate_octet(&result, &timestamp_oct, &result);
    Message::Hash_Function(&result, &B_hash_octet, 0);
    BIG B_hash;
    BIG_fromBytes(B_hash, B_hash_octet.val);
    ECP_mul(&Bpoint, B_hash);

    // Final RHS calculation
    ECP_add(&RHS, &Bpoint);
    ECP_add(&RHS, A);

    // Compare LHS and RHS
    if (!ECP_equals(&LHS, &RHS)) {
        cout << "Message has been Compromised\n";
        return false;
    }

    return true;
}

