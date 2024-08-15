#pragma once

#include"Lib/arch.h"
#include"Lib/core.h"
#include"Lib/randapi.h"
#include"Lib/big_B256_56.h"
#include"Lib/ecp_Ed25519.h"
#include"Lib/ecdh_Ed25519.h"

class Key{
    private:
        octet privateKey;
        octet publicKey;
    public:
        Key(csprng *RNG);
        // Key(octet privateKey);
        Key();
        octet getPrivateKey();
        octet getPublicKey();
        void setPrivateKey(octet privateKey);
        void setPublicKey(octet publicKey);

        static void PointGeneration(Ed25519::ECP *G);
        static int generatePublicKey(octet *PrivateKey, octet *publicKey, Ed25519::ECP *generatorPoint);
        static int generatePrivateKey(csprng *randomNumberGenerator, octet *PrivateKey);
};