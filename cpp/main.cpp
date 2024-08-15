#include <bits/stdc++.h>
#include "Lib/core.h"
#include "Vehicle.h"
#include "Message.h"
#include"Key.h"
using namespace std;

// using namespace core;

char *StrtoCharstar(string s)
{
    char *c = new char[s.length() + 1];
    strcpy(c, s.c_str());
    return c;
}

int main(){

    Vehicle vehicle;
    // TA ta;
    Message message;

    csprng RNG;
    octet privateKey;
    Ed25519::ECP generator;
    Key::PointGeneration(generator);

    int flag;

    flag = Key::generatePrivateKey(&RNG, &privateKey);
    if(flag != 0){
        cout << "Error generating private key" << endl;
        return 1;
    }

    // Key key = Key(privateKey);
    vehicle.setVehicleKey(Key(privateKey));

    vehicle.requestVerification(); //TODO

    string msg = "Mugiwara"; //
    chrono::system_clock::time_point TS = chrono::system_clock::now(); //
    octet puB; //
    octet priB;
    flag = Key::generatePrivateKey(&RNG, &priB);
    Key::generatePublicKey(&priB, &puB, &generator);
    
    //hash need to be generated
    octet hash = {0, static_cast<int>((msg).size() * sizeof(char)), StrtoCharstar(msg)};
    octet Hashed;
    Message::Hash_Function(&hash, &Hashed, 0);
    message = Message(msg, TS, puB, hash);

    vehicle.sendingMessage(0, 0, message); //TODO
}