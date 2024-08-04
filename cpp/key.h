class key{
    public:
        int EDDSA_KEY_PAIR_GENERATE(csprng *R, octet *D, octet *Q);
        int EDDSA_SIGNATURE(bool ph,octet *D, octet *context,octet *M,octet *SIG);
        bool EDDSA_VERIFY(bool ph,octet *Q,octet *context,octet *M,octet *SIG);
}