namespace BifrostNext.BifrostLSF.MACs
{
    public class IdentityMAC : IMAC
    {
        public const ushort Identifier = 0;

        public string HumanName => "identity MAC";
        public ushort MACIdentifier => Identifier;
        public int OutputLength => 0;
        public int SecretBytes => 0;

        public byte[] Calculate(byte[] message)
        {
            return new byte[0];
        }

        public void Initialize(byte[] secret)
        {
        }
    }
}