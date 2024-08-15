#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message(){
    
}

Message::Message(string message, chrono::system_clock::time_point Timestamp, core::octet B, core::octet hashMsg){
    this->message = message;
    this->Timestamp = Timestamp;
    this->B = B;
    this->hashMsg = hashMsg;
}

string Message::getMessage(){
    return message;
}

chrono::system_clock::time_point Message::getTimestamp(){
    return Timestamp;
}

core::octet Message::getB(){
    return B;
}

core::octet Message::getHashMsg(){
    return hashMsg;
}

void Message::setMessage(string message){
    this->message = message;
}

void Message::setTimestamp(chrono::system_clock::time_point Timestamp){
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
    
    /* The 'n' argument is unused in this function. It is likely that it was included as a placeholder for a future
       modification that would involve a third parameter. The 'n' value is not used in any of the cases of the switch
       statement. The 'n' value is instead used in the default case, which is an empty case and therefore does not
       have any effect on the function.

       Therefore, the 'n' argument can be safely removed from the function signature without affecting the behavior
       of the code. */
    int n = -1;
    GPhash(SHA256, 32, output, 32, pad, input, n, NULL);

    // Map octet hash to Zp*
    BIG x, prime;
    BIG_fromBytes(x, output->val); // Convert hash bytes to BIG number
    BIG_zero(prime);               // Initialize BIG 'prime' to zero
    BIG_rcopy(prime, Modulus);     // Copy the constant Modulus value to 'prime'
    BIG_mod(x, prime);             // Take x mod prime
    output->len = 32;
    output->max = 32;
    output->val = new char[32];
    BIG_toBytes(output->val, x);   // Convert the BIG number back to bytes
    
    cout << "Hashed" << endl;
}

/* Concatenate two octet strings */
void Message::Concatenate_octet(octet *data1, octet *data2, octet *result)
{
    int total_length = data1->len + data2->len;
    result->len = total_length;
    memcpy(result->val, data1->val, data1->len);
    memcpy(result->val + data1->len, data2->val, data2->len);
}

// // Concatenate two BIG numbers
// void Message::concatenate_values(B256_56::BIG point1, B256_56::BIG point2, octet *result)
// {
//     using namespace B256_56;
//     octet p1, p2;
//     p1.len = NLEN_B256_56;
//     p2.len = NLEN_B256_56;

//     BIG_toBytes(p1.val, point1);
//     BIG_toBytes(p2.val, point2);
//     Concatenate_octet(&p1, &p2, result);
//     cout << "Concatenated" << endl;
// }

void Message::add_octets(octet *data1, octet *data2, octet *result){
    //convert data in data1 and data2 to BIG
    BIG point1, point2;
    BIG_fromBytes(point1, data1->val);
    BIG_fromBytes(point2, data2->val);
    //add the two BIGs
    BIG sum;
    BIG_add(sum, point1, point2);
    //convert the sum to octet
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
