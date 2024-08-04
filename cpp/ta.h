class ta{

    private:
    map<int, long long> Dictionary;

    long long groupPrivateKey;
    long long groupPublicKey;

    public:
        ta();
        ~ta();
        long long privateKeyGeneration();
        long long publicKeyGeneration();
        long long validSignature(const BIG rId, long long publicKey, Hash);
};