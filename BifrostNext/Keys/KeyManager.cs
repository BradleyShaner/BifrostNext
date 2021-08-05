using BifrostNext;
using BifrostNext.BifrostLSF;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace BifrostNext.Keys
{
    public static class KeyManager
    {
        public static int maxKeyThreads = 1;
        public static int keysToPreCalculate = 5;
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
                if (precomputedKeys.Count < keysToPreCalculate)
                {
                    GenerateKeys();
                    keysGenerated++;
                }
            }
        }

        private static void GenerateKeys()
        {
            var (ca, priv, sign) = CertManager.GenerateKeys();
            logger.Trace($"Computing new connection key..");
            precomputedKeys.Enqueue(new KeyData(ca, priv, sign));
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
                logger.Warn("No pre-computed keys were found, generating a new keypair..");
                GenerateKeys();
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

        public static void MonitorKeyGeneration(CancellationToken serverCancellationToken, int preCalculateKeyCount = 0)
        {

            if (preCalculateKeyCount == -1)
                return;

            logger.Debug("Starting KeyGenerationMonitor thread..");
            if (Environment.ProcessorCount < 4)
                maxKeyThreads = 1;
            else
                maxKeyThreads = Environment.ProcessorCount / 4;

            if (preCalculateKeyCount <= 0)
                keysToPreCalculate = maxKeyThreads * 2;
            else
                keysToPreCalculate = preCalculateKeyCount;

            int stepping;
            int threadsToBeRunning = 0;

            while (!serverCancellationToken.IsCancellationRequested)
            {

                if (threadsToBeRunning != 0 && currentKeyThreads >= threadsToBeRunning)
                {
                    Thread.Sleep(100);
                    continue;
                }

                if (keysToPreCalculate <= AvailablePrecomputedKeys)
                {
                    Thread.Sleep(100);
                    continue;
                }

                stepping = keysToPreCalculate / maxKeyThreads;

                if ((maxKeyThreads * 2) > keysToPreCalculate)
                {
                    threadsToBeRunning = 1;
                    stepping = keysToPreCalculate - AvailablePrecomputedKeys;
                }
                else
                {
                    if (AvailablePrecomputedKeys == 0)
                        threadsToBeRunning = keysToPreCalculate / stepping;
                    else
                        threadsToBeRunning = (keysToPreCalculate - AvailablePrecomputedKeys) / stepping;

                    if (threadsToBeRunning != 0 && (currentKeyThreads >= threadsToBeRunning))
                        continue;

                    if (threadsToBeRunning == 0)
                    {
                        threadsToBeRunning = 1;
                        stepping = keysToPreCalculate - AvailablePrecomputedKeys;
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
                            logger.Trace($"KeyGeneration task {taskResult.Id} has finished. Total Available Keys: {AvailablePrecomputedKeys}");
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