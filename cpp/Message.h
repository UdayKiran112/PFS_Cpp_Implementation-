#include <bits/stdc++.h>
using namespace std;

class Message{
    private:
        string message;
        chrono::system_clock::time_point Timestamp;
        int B; // Public Key Type
        int hashMsg; //64 bitss less than multiple of 512 bits
    public:
        Message();
        Message(string message, chrono::system_clock::time_point Timestamp, int B, int hashMsg);
        string getMessage();
        chrono::system_clock::time_point getTimestamp();
        int getB();
        int getHashMsg();
        void setMessage(string message);
        void setTimestamp(chrono::system_clock::time_point Timestamp);
        void setB(int B);
        void setHashMsg(int hashMsg);
};