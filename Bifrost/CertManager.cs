using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BifrostLSF
{
    public static class CertManager
    {
        private static object _KnownCertificateLock = new object();
        private static string CertificateAuthorityPrivateKey;
        private static string CertificateAuthorityPublicKey;
        private static List<CertAuthInfo> KnownCertificates;

        private static Logger logger = Bifrost.LogManager.GetCurrentClassLogger();

        public static void AddKnownCertificateAuthority(string name, string hash, string certAuthorityPublicKey)
        {
            bool save = false;
            lock (_KnownCertificateLock)
            {
                var item = KnownCertificates.FirstOrDefault(x => x.hash == hash);

                if (item != null)
                {
                    logger.Warn($"Certificate for {item.name} is already known.");
                    return;
                }
                KnownCertificates.Add(new CertAuthInfo(name, hash, certAuthorityPublicKey));
                save = true;
            }

            if (save)
                SaveKnownCertificates();
        }

        public static void GenerateCertificateAuthority(string caPath = "")
        {
            string privCaKeyPath;

            if (string.IsNullOrWhiteSpace(caPath))
            {
                caPath = $"{Environment.MachineName}.ca";
            }

            privCaKeyPath = caPath.ToLower().Replace(".ca", ".privkey");

            // This is the CA pub/priv key. If they don't exist for this machine, create new ones..
            if (!File.Exists($"{caPath}") || !File.Exists($"{privCaKeyPath}"))
            {
                logger.Info("CA files don't exist, generating..");

                var CertificateAuthority = new RSACryptoServiceProvider(2048);

                var parameters = CertificateAuthority.ExportParameters(true);
                var pair = DotNetUtilities.GetRsaKeyPair(parameters);

                //write the CA pub/priv keys
                WriteFile($"{caPath}", RsaHelpers.PemSerialize(pair.Public));
                WriteFile($"{privCaKeyPath}", RsaHelpers.PemSerialize(pair));
                CertificateAuthorityPrivateKey = RsaHelpers.PemSerialize(pair);
                CertificateAuthorityPublicKey = RsaHelpers.PemSerialize(pair.Public);
            }

            return;
        }

        public static (string certAuthority, string clientPrivateKey, byte[] clientSignKey) GenerateKeys(string caPath = "")
        {
            AsymmetricCipherKeyPair certAuthority;
            string privCaKeyPath;

            if (string.IsNullOrWhiteSpace(caPath))
            {
                caPath = $"{Environment.MachineName}.ca";
            }

            privCaKeyPath = caPath.ToLower().Replace(".ca", ".privkey");

            if (String.IsNullOrWhiteSpace(CertificateAuthorityPrivateKey))
                CertificateAuthorityPrivateKey = File.ReadAllText($"{privCaKeyPath}");

            string caPrivKey = CertificateAuthorityPrivateKey;
            certAuthority = (AsymmetricCipherKeyPair)RsaHelpers.PemDeserialize(caPrivKey);

            if (String.IsNullOrWhiteSpace(CertificateAuthorityPublicKey))
                CertificateAuthorityPublicKey = RsaHelpers.PemSerialize(certAuthority.Public);

            logger.Trace("Generating new keys..");
            var key = new RSACryptoServiceProvider(2048);
            var parameters = key.ExportParameters(true);
            var pair = DotNetUtilities.GetRsaKeyPair(parameters);

            string pub = RsaHelpers.PemSerialize(pair.Public);
            string priv = RsaHelpers.PemSerialize(pair);

            if (certAuthority != null)
            {
                logger.Trace("Signing keys..");
                var signature = RsaHelpers.SignData(Encoding.UTF8.GetBytes(pub), certAuthority);

                logger.Trace("Verifying key signature...");
                if (RsaHelpers.VerifyData(Encoding.UTF8.GetBytes(pub), signature, certAuthority))
                {
                    logger.Trace("Signature validated!");

                    return (CertificateAuthorityPublicKey, priv, signature);
                }
                logger.Error("Signature validation failed!");
            }
            return (null, null, null);
        }

        public static bool IsCertificateTrusted(string hash)
        {
            lock (_KnownCertificateLock)
            {
                var item = KnownCertificates.FirstOrDefault(x => x.hash == hash);

                if (item != null && item.trusted)
                {
                    return true;
                }

                return false;
            }
        }

        public static RsaKeyParameters RetrievePublicCertificateByHash(string hash)
        {
            if (KnownCertificates == null)
                LoadKnownCertificates();

            lock (_KnownCertificateLock)
            {
                var item = KnownCertificates.FirstOrDefault(x => x.hash == hash);

                if (item != null)
                    return (RsaKeyParameters)RsaHelpers.PemDeserialize(item.publicKey);
                else
                    return null;
            }
        }

        public static void SaveKnownCertificates()
        {
            lock (_KnownCertificateLock)
            {
                try
                {
                    File.WriteAllText("KnownCerts.json", JsonConvert.SerializeObject(KnownCertificates, Formatting.Indented));
                    logger.Debug("Wrote KnownCerts.json successfully!");
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Unable to write KnownCerts.json!");
                }
            }
        }

        public static void SetCertificateTrusted(string hash, bool trusted)
        {
            bool save = false;
            lock (_KnownCertificateLock)
            {
                var item = KnownCertificates.FirstOrDefault(x => x.hash == hash);

                if (item != null && item.trusted != trusted)
                {
                    logger.Debug($"SetCertificateTrusted: {hash}: {trusted}");
                    item.trusted = trusted;
                    save = true;
                }
            }

            if (save)
                SaveKnownCertificates();
        }

        private static void LoadKnownCertificates()
        {
            try
            {
                lock (_KnownCertificateLock)
                    KnownCertificates = JsonConvert.DeserializeObject<List<CertAuthInfo>>(File.ReadAllText("KnownCerts.json"));
            }
            catch (Exception ex)
            {
                logger.Warn("LoadKnownCertificates failed. Creating new KnownCerts.json..");

                lock (_KnownCertificateLock)
                    KnownCertificates = new List<CertAuthInfo>();

                SaveKnownCertificates();
            }
        }

        private static void WriteFile(string path, byte[] data)
        {
            logger.Trace("Writing {data.Length} bytes to {path}");
            File.WriteAllBytes(path, data);
        }

        private static void WriteFile(string path, string contents) => WriteFile(path, Encoding.UTF8.GetBytes(contents));
    }

    public class CertAuthInfo
    {
        public string hash;
        public string name;
        public string publicKey;
        public bool trusted;

        public CertAuthInfo(string name, string hash, string certAuthorityPublicKey)
        {
            this.name = name;
            this.hash = hash;
            this.publicKey = certAuthorityPublicKey;
            trusted = false;
        }
    }
}