using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;

namespace BifrostLSF.Ciphers
{
    public class AesGcmCipher : ICipher
    {
        public const ushort Identifier = 2;

        public RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
        private KeyParameter _key;
        private byte[] raw_key;
        public ushort CipherIdentifier { get { return Identifier; } }
        public string HumanName { get { return "AES-GCM"; } }
        public byte[] Key { get { return raw_key; } set { raw_key = value; _key = new KeyParameter(raw_key); } }
        public int SecretBytes { get { return 16; } }

        public AesGcmCipher()
        {
        }

        public byte[] Decrypt(byte[] data)
        {
            var daes = new GcmBlockCipher(new AesFastEngine());

            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[data.Length - iv.Length];

            Array.Copy(data, iv, iv.Length);
            Array.Copy(data, iv.Length, ciphertext, 0, ciphertext.Length);

            var parameters = new AeadParameters(_key, 128, iv);
            daes.Init(false, parameters);

            var final_message = new byte[daes.GetOutputSize(ciphertext.Length)];
            int len = daes.ProcessBytes(ciphertext, 0, ciphertext.Length, final_message, 0);
            daes.DoFinal(final_message, len);

            return final_message;
        }

        public byte[] Encrypt(byte[] data)
        {
            var eaes = new GcmBlockCipher(new AesFastEngine());

            MemoryStream ms = new MemoryStream();

            byte[] iv = new byte[16];
            RNG.GetBytes(iv);

            var parameters = new AeadParameters(_key, 128, iv);
            eaes.Init(true, parameters);

            var ciphertext = new byte[eaes.GetOutputSize(data.Length)];
            int len = eaes.ProcessBytes(data, 0, data.Length, ciphertext, 0);
            eaes.DoFinal(ciphertext, len);

            ms.Write(iv, 0, iv.Length);
            ms.Write(ciphertext, 0, ciphertext.Length);

            return ms.ToArray();
        }

        public void Initialize(byte[] secret)
        {
            Key = secret;
        }
    }
}