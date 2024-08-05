#include "Lib/arch.h"
#include "Lib/ecp_Ed25519.h"
using namespace B256_56;

class vehicle{
    private:
        int rId;
        Point vehiclePublicKey;
        long long vehiclePrivateKey;
        Point signature;

    public:
        vehicle(int rId, Point generator);
        ~vehicle();

        int getRId() const;
        void setRId(int rId);
        Point getVehiclePublicKey() const;
        void setVehiclePublicKey(Point publicKey);
        long long getVehiclePrivateKey() const;
        void setVehiclePrivateKey(long long privateKey);
        Point getSignature() const;
        void setSignature(Point signature);

        void requestVerification(const BIG rId, long long publicKey);
};