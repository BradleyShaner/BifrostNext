using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Text;

namespace BifrostNext
{
    public class QuickRSA
    {

        public QuickRSA()
        {
            CertManager.CheckCertAuthority();
        }

        public string RsaDecryptWithPrivate(string base64Input, string privateKey = "")
        {

            if (privateKey.Length == 0)
                privateKey = CertManager._certificateAuthorityPrivateKey;

            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            AsymmetricCipherKeyPair keyPair;
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyPair.Private);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }

        public string RsaDecryptWithPublic(string base64Input, string publicKey = "")
        {

            if (publicKey.Length == 0)
                publicKey = CertManager._certificateAuthorityPublicKey;

            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyParameter);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }


        public string RsaEncryptWithPrivate(string clearText, string privateKey = "")
        {
            if (privateKey.Length == 0)
                privateKey = CertManager._certificateAuthorityPrivateKey;

            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyPair.Private);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }

        public string RsaEncryptWithPublic(string clearText, string publicKey = "")
        {

            if (publicKey.Length == 0)
                publicKey = CertManager._certificateAuthorityPublicKey;

            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyParameter);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }

    }
}