class Key{
    private:
        int privateKey;
        int publicKey; // will change
    public:
        Key();
        Key(int privateKey);
        int getPrivateKey();
        int getPublicKey();
        void setPrivateKey(int privateKey);
        void setPublicKey(int publicKey);

        int generatePublicKey(int randomGenerator);
        int generatePrivateKey(int privateKey);
};