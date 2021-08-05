namespace BifrostNext.BifrostLSF.Ciphers
{
    public interface ICipher
    {
        ushort CipherIdentifier { get; }
        string HumanName { get; }
        byte[] Key { get; set; }
        int SecretBytes { get; }

        byte[] Decrypt(byte[] data);

        byte[] Encrypt(byte[] data);

        void Initialize(byte[] secret);
    }
}