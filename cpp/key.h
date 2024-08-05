#include "point.h"
class key{
    private:
        Point generator;

    public:
        key();
        ~key();
        long long privateKeyGeneration(Point generator);
        Point publicKeyGeneration(long long privateKey);
};