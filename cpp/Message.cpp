#include <bits/stdc++.h>
#include "Message.h"
using namespace std;

Message::Message(){
    
}

Message::Message(string message, int Timestamp, int B, int hashMsg){
    this->message = message;
    this->Timestamp = Timestamp;
    this->B = B;
    this->hashMsg = hashMsg;
}

string Message::getMessage(){
    return message;
}

int Message::getTimestamp(){
    return Timestamp;
}

int Message::getB(){
    return B;
}

int Message::getHashMsg(){
    return hashMsg;
}

void Message::setMessage(string message){
    this->message = message;
}

void Message::setTimestamp(int Timestamp){
    this->Timestamp = Timestamp;
}

void Message::setB(int B){
    this->B = B;
}

void Message::setHashMsg(int hashMsg){
    this->hashMsg = hashMsg;
}

