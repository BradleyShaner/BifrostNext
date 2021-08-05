using BifrostNext;
using BifrostNext.BifrostLSF;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace BifrostNext.Extended.Keys
{
    public static class KeyManager
    {
        public static int maxKeyThreads = Environment.ProcessorCount / 2;
        public static int precomputeKeyCount = maxKeyThreads * 5;
        public static List<UserConnection> users = new List<UserConnection>();
        private static int currentKeyThreads = 0;
        private static ManualResetEvent keyGeneration = new ManualResetEvent(true);
        private static Logger logger = LogManager.GetCurrentClassLogger();
        private static ConcurrentQueue<KeyData> precomputedKeys = new ConcurrentQueue<KeyData>();
        public static int AvailablePrecomputedKeys { get => precomputedKeys.Count; }

        public static void GenerateConnectionKeys(CancellationToken token, int keysToGenerate = 1)
        {
            logger.Trace("GenerateConnectionKeys started. keysToGenerate: " + keysToGenerate);
            int keysGenerated = 0;
            while (!token.IsCancellationRequested && (keysToGenerate > keysGenerated))
            {
                if (precomputedKeys.Count < precomputeKeyCount)
                {
                    var (ca, priv, sign) = CertManager.GenerateKeys();
                    logger.Trace($"Computing new connection key..");
                    precomputedKeys.Enqueue(new KeyData(ca, priv, sign));
                    keysGenerated++;
                }
            }
        }

        public static (string certAuthority, string privateKey, byte[] signKey) GetNextAvailableKeys()
        {
            string ca = "";
            string priv = "";
            byte[] sign = null;

            Stopwatch timeout = Stopwatch.StartNew();
            KeyData keys = null;
            while (timeout.ElapsedMilliseconds < 5000 && !precomputedKeys.TryDequeue(out keys))
            {
                //there are no precomputedkeys available..
                Thread.Sleep(10);
            }

            timeout.Stop();

            if (keys == null || timeout.ElapsedMilliseconds > 5000)
            {
                logger.Error("GetNextAvailableKeys timed out!");
                return ("", "", new byte[] { });
            }

            ca = keys.ServerCertificateAuthority;
            priv = keys.PrivateKey;
            sign = keys.SignKey;

            return (ca, priv, sign);
        }

        public static void MonitorKeyGeneration(CancellationToken serverCancellationToken)
        {
            logger.Debug("Starting KeyGenerationMonitor thread..");
            int stepping;

            while (!serverCancellationToken.IsCancellationRequested)
            {
                if (currentKeyThreads >= maxKeyThreads)
                {
                    Thread.Sleep(100);
                    continue;
                }

                if (precomputeKeyCount == AvailablePrecomputedKeys)
                {
                    Thread.Sleep(100);
                    continue;
                }

                int threadsToBeRunning = 0;
                stepping = precomputeKeyCount / maxKeyThreads;

                if ((maxKeyThreads * 2) > precomputeKeyCount)
                {
                    threadsToBeRunning = 1;
                    stepping = precomputeKeyCount - AvailablePrecomputedKeys;
                }
                else
                {
                    if (AvailablePrecomputedKeys == 0)
                        threadsToBeRunning = precomputeKeyCount / stepping;
                    else
                        threadsToBeRunning = (precomputeKeyCount - AvailablePrecomputedKeys) / stepping;

                    if (threadsToBeRunning != 0 && (currentKeyThreads >= threadsToBeRunning))
                        continue;

                    if (threadsToBeRunning == 0)
                    {
                        threadsToBeRunning = 1;
                        stepping = precomputeKeyCount - AvailablePrecomputedKeys;
                    }

                    if (threadsToBeRunning > maxKeyThreads)
                        threadsToBeRunning = maxKeyThreads;
                }

                if (stepping == 1)
                    threadsToBeRunning = 1;

                threadsToBeRunning -= currentKeyThreads;

                if (threadsToBeRunning > 0)
                {
                    logger.Trace("Starting new KeyGeneration threads: " + threadsToBeRunning + " keysToGenerate: " + (stepping * threadsToBeRunning));
                    for (int i = 0; i < threadsToBeRunning; i++)
                    {
                        Task.Factory.StartNew(() => GenerateConnectionKeys(serverCancellationToken, stepping),
                        serverCancellationToken,
                        TaskCreationOptions.None,
                        TaskScheduler.Default).ContinueWith(taskResult =>
                        {
                            currentKeyThreads--;
                            logger.Trace($"KeyGeneration task {taskResult.Id} has finished.");
                        });
                        currentKeyThreads++;
                    }
                }

                Thread.Sleep(100);
            }
        }
    }

    public class KeyData
    {
        public string ClientCertificateAuthority;
        public string PrivateKey;
        public string ServerCertificateAuthority;
        public byte[] SignKey;

        public KeyData(string serverCa, string priv, byte[] sign)
        {
            ServerCertificateAuthority = serverCa;
            PrivateKey = priv;
            SignKey = sign;
        }

        public KeyData()
        {
        }
    }
}