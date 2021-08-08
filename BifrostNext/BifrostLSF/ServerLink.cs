using BifrostNext.BifrostLSF.Ciphers;
using BifrostNext.BifrostLSF.MACs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace BifrostNext.BifrostLSF
{
    public class ServerLink : EncryptedLink
    {
        private Logger Log = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Creates a new EncryptedLink object from the perspective of a server.
        /// </summary>
        /// <param name="tunnel">The ITunnel to use.</param>
        /// <param name="noAuthentication">If auth_client is set to false, the client's RSA public key and key exchange parameters are checked against the certificate authority.</param>
        public ServerLink(ITunnel tunnel, bool noAuthentication = false, bool rememberRemoteCertAuthority = false)
        {
            Tunnel = tunnel;
            NoAuthentication = noAuthentication;
            RememberRemoteCertAuthority = rememberRemoteCertAuthority;
        }

        public EncryptedLink GetEncryptedLink()
        {
            return (EncryptedLink)this;
        }

        public HandshakeResult PerformHandshake(List<CipherSuiteIdentifier> allowed_suites = null)
        {
            allowed_suites = allowed_suites ?? (AllowedSuites.Any() ? AllowedSuites : SaneSuites);

            ManualResetEvent done = new ManualResetEvent(false);
            HandshakeResult result = new HandshakeResult(HandshakeResultType.Timeout, "Handshake timed out.");

            var thread = Utilities.StartThread(delegate
            {
                try
                {
                    result = _PerformHandshake(allowed_suites);
                }
                catch (Exception ex)
                {
                    result = new HandshakeResult(HandshakeResultType.Other, "Exception occurred.");
                    Log.Trace(ex);
                }
                done.Set();
            });

            if (!done.WaitOne(10000))
            {
                Close();
                Thread.Sleep(100);
                thread.Abort();
            }

            return result;
        }

        /// <summary>
        /// Perform a server-side handshake.
        /// </summary>
        /// <returns>A HandshakeResult class containing information about the handshake attempt.</returns>
        private HandshakeResult _PerformHandshake(List<CipherSuiteIdentifier> allowed_suites)
        {
            Suite = new CipherSuite()
            {
                Cipher = new IdentityCipher(),
                MAC = new IdentityMAC()
            };

            Message msg = Receive();

            Log.Debug(msg.Type);

            if (msg == null)
            {
                var result = new HandshakeResult(HandshakeResultType.ConnectionClosed, "Connection closed.");
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            if (!msg.CheckType(MessageType.ClientHello, 0x00))
            {
                var result = new HandshakeResult(HandshakeResultType.UnexpectedMessage, "Received message of type {0}/0x{1:X2} while expecting ClientHello/0x00. Terminating handshake.", msg.Type, msg.Subtype);
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            var peer_suites = new List<CipherSuiteIdentifier>();
            var suite_data = msg.Store["allowed_suites"];

            Log.Debug("{0} bytes of allowed suites", suite_data.Length);

            for (int i = 0; i < suite_data.Length; i += CipherSuiteIdentifier.IdentifierLength)
            {
                peer_suites.Add(new CipherSuiteIdentifier(suite_data, i));
            }

            peer_suites = peer_suites.Distinct().ToList();

            var suite_scores = new Dictionary<CipherSuiteIdentifier, int>();

            for (int i = 0; i < allowed_suites.Count; i++)
            {
                for (int j = 0; j < peer_suites.Count; j++)
                {
                    var our_suite = allowed_suites[i];
                    var their_suite = peer_suites[j];

                    if (our_suite != their_suite)
                        continue;

                    suite_scores[our_suite] = i + j;
                }
            }

            var chosen_suite = suite_scores.OrderBy(p => p.Value).First().Key;

            SendMessage(MessageHelpers.CreateServerHello(this, chosen_suite));

            Suite = chosen_suite.CreateSuite();
            var real_cipher = Suite.Cipher;
            var real_mac = Suite.MAC;

            Suite.Cipher = new IdentityCipher(); // temporarily set suite cipher to IdentityCipher so we can continue handshake
            Suite.MAC = new IdentityMAC(); // likewise
            Suite.Initialize();

            msg = Receive();

            if (!msg.CheckType(MessageType.AuthRequest, 0x00))
            {
                var result = new HandshakeResult(HandshakeResultType.UnexpectedMessage, "Received message of type {0}/0x{1:X2} while expecting AuthRequest/0x00. Terminating handshake.", msg.Type, msg.Subtype);
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            byte[] rsa_public_key = msg.Store["rsa_public_key"];
            byte[] ca_public_key = msg.Store["ca_public_key"];
            byte[] rsa_signature = msg.Store["rsa_signature"];
            byte[] ecdh_public_key = msg.Store["ecdh_public_key"];
            byte[] ecdh_signature = msg.Store["ecdh_signature"];
            string cert_name = Encoding.UTF8.GetString(msg.Store["cert_name"]);
            PeerSignature = rsa_signature;

            remoteCertificateHash = Convert.ToBase64String(SHA.ComputeHash(msg.Store["ca_public_key"]));
            RemoteCertificateAuthority = CertManager.RetrievePublicCertificateByHash(remoteCertificateHash);
            //RemoteCertificate = CertManager.RetrievePrivateCertificateByHash(remoteCertificateHash);

            if (RemoteCertificateAuthority != null)
            {
                TrustedCertificateUsed = CertManager.IsCertificateTrusted(remoteCertificateHash);
                Log.Debug("Known certificate found and loaded: " + (TrustedCertificateUsed ? "Trusted" : "Untrusted"));
            }
            else if (RememberRemoteCertAuthority)
            {
                Log.Debug("Known certificate not found, adding..");
                CertManager.AddKnownCertificateAuthority(cert_name, remoteCertificateHash, Encoding.UTF8.GetString(ca_public_key));
                RemoteCertificateAuthority = CertManager.RetrievePublicCertificateByHash(remoteCertificateHash);
                TrustedCertificateUsed = false;
            }

            byte[] timestamp = msg.Store["timestamp"];
            DateTime timestamp_dt = MessageHelpers.GetDateTime(BitConverter.ToInt64(timestamp, 0));
            TimeSpan difference = (DateTime.UtcNow - timestamp_dt).Duration();

            if (msg.Store.ContainsKey("attestation_token"))
                AttestationToken = msg.Store["attestation_token"];

            if (!timestamp.SequenceEqual(ecdh_public_key.Skip(ecdh_public_key.Length - 8)))
            {
                var result = new HandshakeResult(HandshakeResultType.UntrustedTimestamp, "Timestamp mismatch between ECDH public key and explicit timestamp. Terminating handshake.");
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            if (difference > MaximumTimeMismatch)
            {
                var result = new HandshakeResult(HandshakeResultType.ReplayAttack, "Timestamp difference between client and server exceeds allowed window of {0}(provided timestamp is {1}, our clock is {2}). Terminating handshake.", MaximumTimeMismatch, timestamp_dt, DateTime.UtcNow);
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            Log.Debug("Clock drift between peers is {0}.", difference);

            if (!NoAuthentication)
            {
                if (RemoteCertificateAuthority != null)
                {
                    if (!RsaHelpers.VerifyData(rsa_public_key, rsa_signature, RemoteCertificateAuthority))
                    {
                        if (!RsaHelpers.VerifyData(rsa_public_key, rsa_signature, CertificateAuthority))
                        {
                            var result = new HandshakeResult(HandshakeResultType.UntrustedStaticPublicKey, "1. Failed to verify RSA public key against certificate authority. Terminating handshake.");
                            Log.Error(result.Message);
                            Tunnel.Close();
                            return result;
                        }
                    }
                }
                else if (!RsaHelpers.VerifyData(rsa_public_key, rsa_signature, CertificateAuthority))
                {
                    var result = new HandshakeResult(HandshakeResultType.UntrustedStaticPublicKey, "2. Failed to verify RSA public key against certificate authority. Terminating handshake.");
                    Log.Error(result.Message);
                    Tunnel.Close();
                    return result;
                }
            }

            RsaKeyParameters parameters = (RsaKeyParameters)RsaHelpers.PemDeserialize(Encoding.UTF8.GetString(rsa_public_key));

            if (!NoAuthentication && !RsaHelpers.VerifyData(ecdh_public_key, ecdh_signature, parameters))
            {
                var result = new HandshakeResult(HandshakeResultType.UntrustedEphemeralPublicKey, "1. Failed to verify ECDH public key authenticity. Terminating handshake.");
                Log.Error(result.Message);
                Tunnel.Close();
                return result;
            }

            Suite.SharedSalt = new byte[16];
            RNG.GetBytes(Suite.SharedSalt);

            SendMessage(MessageHelpers.CreateAuthResponse(this));

            Suite.Cipher = real_cipher;
            Suite.MAC = real_mac;
            var shared_secret = Suite.FinalizeKeyExchange(ecdh_public_key);

            StartThreads();

            var result_final = new HandshakeResult(HandshakeResultType.Successful, "Handshake successful.");
            result_final.TimeDrift = difference.TotalSeconds;
            Log.Debug(result_final.Message);
            Log.Debug("Cipher: {0}, key exchange: {1}, MAC: {2}", Suite.Cipher.HumanName, Suite.KeyExchange.HumanName, Suite.MAC.HumanName);
            return result_final;
        }
    }
}