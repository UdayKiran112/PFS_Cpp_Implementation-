#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message(){

}

Message::~Message() {
    delete[] message.val;
    delete[] Timestamp.val;
    delete[] B.val;
    delete[] finalMsg.val;
}

Message::Message(string message, chrono::system_clock::time_point Timestamp, core::octet B){
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    timestamp_to_octet(Timestamp, &this->Timestamp);

    this->B = B;
}

core::octet Message::getMessage(){
    return message;
}

core::octet Message::getTimestamp(){
    return Timestamp;
}

core::octet Message::getB(){
    return B;
}

core::octet Message::getFinalMsg(){
    return finalMsg;
}

void Message::setMessage(core::octet message){
    this->message = message;
}

void Message::setTimestamp(core::octet Timestamp){
    this->Timestamp = Timestamp;
}

void Message::setB(core::octet B){
    this->B = B;
}

void Message::setFinalMsg(core::octet finalMsg){
    this->finalMsg = finalMsg;
}

using namespace core;
using namespace Ed25519;
using namespace B256_56;
using namespace F25519;

void Message::Hash_Function(octet *input, octet *output, int pad){
    int n = -1;
    GPhash(SHA256, 32, output, 32, pad, input, n, nullptr);

    BIG x, prime;
    BIG_fromBytes(x, output->val);
    BIG_zero(prime);
    BIG_rcopy(prime, Modulus);
    BIG_mod(x, prime);
    output->len = 32;
    output->max = 32;
    output->val = new char[32];
    BIG_toBytes(output->val, x);
}

void Message::Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;
    result->len = total_length;
    memcpy(result->val, data1->val, data1->len);
    memcpy(result->val + data1->len, data2->val, data2->len);
}

void Message::add_octets(octet *data1, octet *data2, octet *result){
    BIG point1, point2;
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    BIG sum;
    BIG_add(sum, point1, point2);
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, sum);
}

void Message::timestamp_to_octet(chrono::system_clock::time_point timeStamp, octet* result)
{
    using namespace chrono;
    auto time_since_epoch = timeStamp.time_since_epoch();
    auto millis = duration_cast<milliseconds>(time_since_epoch).count();

    // Truncate to 32 bits (4 bytes)
    uint32_t truncated_millis = static_cast<uint32_t>(millis);

    result->len = 4;
    result->max = 4;
    result->val = new char[4];
    unsigned char* ptr = (unsigned char*)result->val;

    // Store the 32-bit (4-byte) truncated value into the octet
    for (int i = 3; i >= 0; i--)
    {
        ptr[i] = truncated_millis & 0xFF;
        truncated_millis >>= 8;
    }
}

void Message::multiply_octet(octet *data1, octet *data2, octet *result){
    BIG point1, point2;
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    BIG product;
    BIG_mul(product, point1, point2);
    result->len = 32;
    result->max = 32;
    result->val = new char[32];
    BIG_toBytes(result->val, product);
}