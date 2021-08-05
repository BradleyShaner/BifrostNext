using System.Security.Cryptography;

namespace BifrostNext.BifrostLSF.MACs
{
    public class HMACSHA : IMAC
    {
        public const ushort Identifier = 1;
        private byte[] _secret;
        public string HumanName => "HMAC-SHA256";
        public ushort MACIdentifier => Identifier;

        public int OutputLength => 32;
        public int SecretBytes => 64;

        public HMACSHA()
        {
        }

        public byte[] Calculate(byte[] message)
        {
            var hmac = new HMACSHA256(_secret);
            return hmac.ComputeHash(message);
        }

        public void Initialize(byte[] secret)
        {
            _secret = secret;
        }
    }
}