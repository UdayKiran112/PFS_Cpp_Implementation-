#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message(){

}

Message::~Message() {
    delete[] message.val;
    delete[] Timestamp.val;
    delete[] B.val;
    delete[] hashMsg.val;
}

Message::Message(string message, chrono::system_clock::time_point Timestamp, core::octet B){
    this->message.len = message.size();
    this->message.max = message.size();
    this->message.val = new char[message.size()];
    memcpy(this->message.val, message.c_str(), message.size());

    timestamp_to_octet(Timestamp, &this->Timestamp);

    this->B = B;

    octet temp1, temp2;
    Concatenate_octet(&this->message, &this->Timestamp, &temp1);
    Concatenate_octet(&temp1, &this->B, &temp2);
    Hash_Function(&temp2, &hashMsg, 0);
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

core::octet Message::getHashMsg(){
    return hashMsg;
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

void Message::setHashMsg(core::octet hashMsg){
    this->hashMsg = hashMsg;
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
    result->len = 8;
    result->max = 8;
    result->val = new char[8];
    unsigned char* ptr = (unsigned char*)result->val;
    for (int i = 7; i >= 0; i--)
    {
        ptr[i] = millis & 0xFF;
        millis >>= 8;
    }
}
