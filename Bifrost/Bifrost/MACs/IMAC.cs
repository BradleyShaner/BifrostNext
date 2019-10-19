namespace BifrostLSF.MACs
{
    public interface IMAC
    {
        string HumanName { get; }
        ushort MACIdentifier { get; }
        int OutputLength { get; }
        int SecretBytes { get; }

        byte[] Calculate(byte[] message);

        void Initialize(byte[] secret);
    }
}