#include <bits/stdc++.h>
using namespace std;

class Message{
    private:
        string message;
        int Timestamp;
        int B; // Public Key Type
        int hashMsg; //64 bitss less than multiple of 512 bits
};