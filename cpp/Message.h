#pragma once

#include <bits/stdc++.h>
#include<chrono>
#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <chrono>
#include "Lib/core.h"
#include "Lib/eddsa_Ed25519.h"
#include "Lib/config_big_B256_56.h"
using namespace std;

// using namespace std;
using namespace std;

class Message{
    private:
        string message;
        chrono::system_clock::time_point Timestamp;
        core::octet B; // Public Key Type
        core::octet hashMsg; //64 bitss less than multiple of 512 bits
    public:
        Message();
        Message(string message, chrono::system_clock::time_point Timestamp, core::octet B, core::octet hashMsg);
        string getMessage();
        chrono::system_clock::time_point getTimestamp();
        core::octet getB();
        core::octet getHashMsg();
        void setMessage(string message);
        void setTimestamp(chrono::system_clock::time_point Timestamp);
        void setB(core::octet B);
        void setHashMsg(core::octet hashMsg);

        static void Concatenate_octet(octet *data1, octet *data2, octet *result);
        // static void concatenate_values(B256_56::BIG point1, B256_56::BIG point2, octet *result);
        static void Hash_Function(octet *input, octet *output, int pad);
        static void timestamp_to_octet(chrono::system_clock::time_point timeStamp, octet* result);
        static void add_octets(octet *data1, octet *data2, octet *result);
};

#endif // MESSAGE_H