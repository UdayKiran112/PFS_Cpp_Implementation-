#include <bits/stdc++.h>
#include <chrono>
#include "Vehicle.h"
using namespace std;

bool signMessage(bool ph, octet *privateKey, octet *context, octet *message, octet *signature);
void sendingMessage(core::octet vehiclePrivateKey, core::octet signatureKey, Message message);

Vehicle::Vehicle(octet registrationId, Key vehicleKey, octet signatureKey, octet A, TA ta)
{
    this->registrationId = registrationId;
    this->vehicleKey = vehicleKey;
    this->signatureKey = signatureKey;
    this->A = A;
    this->ta = ta;
}

Vehicle::Vehicle() {}

Vehicle::Vehicle(csprng *RNG)
{
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
void Vehicle::requestVerification(csprng *RNG)
{
    octet signkey, virpubkey;
    octet publicKey = this->getVehicleKey().getPublicKey();
    auto temp = this->registrationId;
    this->ta.validateRequest(RNG, &temp, &publicKey, &signkey, &virpubkey);
    this->setSignatureKey(signkey);
    this->setA(virpubkey);
}

static char *StrtoCharstar(string s)
{
    char *c = new char[s.length() + 1];
    strcpy(c, s.c_str());
    return c;
}

// void sendingMessage(csprng *RNG, core::octet vehiclePrivateKey, core::octet signatureKey, string message, octet *B, Message msg, octet *SIG)
// {
//     //
//     bool x = signMessage(RNG, &vehiclePrivateKey, &signatureKey, message, SIG, B, msg);
//     if (!x)
//     {
//         cout << "No Signature Generated";
//         return;
//     }

//     cout << "Signature= 0x";
//     OCT_output(&SIG);
// }

bool Vehicle::signMessage(csprng *RNG, octet *privateKey, octet *SignatureKey, string message, octet *signedMessage, octet *B, Message msg)
{
    using namespace Ed25519;
    Key randKey(RNG);

    // Generate B
    OCT_copy(B, &randKey.getPublicKey());
    msg = Message(message, chrono::system_clock::now(), *B);

    // Generate Signature --> signedMessage = SignatureKey + privateKey + randKey.getPrivateKey() * H(M || T || B)
    octet *result;
    Message::add_octets(privateKey, SignatureKey, result); // signature Key + private Key
    octet *part3;
    Message::multiply_octet(&randKey.getPrivateKey(), &msg.getHashMsg(), part3); // b* H(M || T || B)

    Message::add_octets(result, part3, signedMessage); // signature Key + private Key + b* H(M || T || B)

    return true;
}

static bool verifyMessage(bool ph, octet *publicKey, octet *context, octet *message, octet *signature)
{
    return EDDSA_VERIFY(ph, publicKey, context, message, signature);
}

#define T_replay 1000

bool Vehicle::Validate_Message(Ed25519::ECP *GeneratorPoint, octet *signedMessage, Ed25519::ECP *PublicKey, Ed25519::ECP *VehiclePublicKey, Ed25519::ECP *B, Ed25519::ECP *A, chrono::system_clock::time_point timeStamp, octet *Message)
{
    using namespace B256_56;
    auto now = chrono::system_clock::now();
    if (chrono::duration_cast<chrono::milliseconds>(now - timeStamp).count() > T_replay)
    {
        return false;
    }

    ECP LHS, RHS, P, Apoint, Bpoint, PubKey, VehPubKey;
    ECP_copy(&P, GeneratorPoint);
    ECP_copy(&PubKey, PublicKey);
    ECP_copy(&VehPubKey, VehiclePublicKey);
    ECP_copy(&Apoint, A);
    ECP_copy(&Bpoint, B);

    BIG signedMessageHash;
    BIG_fromBytes(signedMessageHash, signedMessage->val);
    ECP_mul(&P, signedMessageHash);
    ECP_copy(&LHS, &P);

    ECP_copy(&RHS, PublicKey);
    ECP_add(&RHS, VehiclePublicKey);

    ECP_add(VehiclePublicKey, A);
    octet A_hash_octet;
    ECP_toOctet(&A_hash_octet, VehiclePublicKey, true);
    octet Hash_A_out;
    Message::Hash_Function(&A_hash_octet, &Hash_A_out, 0);
    BIG A_hash;
    BIG_fromBytes(A_hash, A_hash_octet.val);
    ECP_mul(A, A_hash);

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

    ECP_add(&RHS, &Bpoint);
    ECP_add(&RHS, A);

    if (!ECP_equals(&LHS, &RHS))
    {
        cout << "Message has been Compromised\n";
        return false;
    }

    return true;
}
