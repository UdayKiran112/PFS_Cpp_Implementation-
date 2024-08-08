#include <bits/stdc++.h>
using namespace std;

class Message{
    private:
        string message;
        int Timestamp;
        int B; // Public Key Type
        int hashMsg; //64 bitss less than multiple of 512 bits
    public:
        Message();
        Message(string message, int Timestamp, int B, int hashMsg);
        string getMessage();
        int getTimestamp();
        int getB();
        int getHashMsg();
        void setMessage(string message);
        void setTimestamp(int Timestamp);
        void setB(int B);
        void setHashMsg(int hashMsg);
};