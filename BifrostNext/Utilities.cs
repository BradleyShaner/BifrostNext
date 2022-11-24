using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;

namespace BifrostNext
{
    public enum SerilogLogLevel
    {
        Verbose = 0,
        Debug = 1,
        Information = 2,
        Warning = 3,
        Error = 4,
        Fatal = 5
    }

    public class Utilities
    {
        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        public static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dstream.CopyTo(output);
            }
            return output.ToArray();
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, string args)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(args);
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { args });
                    }
                    catch { }
                }
            }
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, ClientData clientData, Dictionary<string, byte[]> arg2)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(new object[] { clientData, arg2 });
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { clientData, arg2 });
                    }
                    catch { }
                }
            }
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, Client client, bool arg2)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(new object[] { client, arg2 });
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { client, arg2 });
                    }
                    catch { }
                }
            }
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, Client client, Dictionary<string, byte[]> arg2)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(new object[] { client, arg2 });
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { client, arg2 });
                    }
                    catch { }
                }
            }
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, Dictionary<string, byte[]> args)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(args);
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { args });
                    }
                    catch { }
                }
            }
        }

        public static void RaiseEventOnUIThread(Delegate theEvent, ClientData clientData)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(clientData);
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { clientData });
                    }
                    catch { }
                }
            }
        }

        internal static void RaiseEventOnUIThread(Delegate theEvent, RsaKeyParameters remoteCertificateAuthority, string remoteCertificateHash)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    try
                    {
                        d.DynamicInvoke(remoteCertificateAuthority, remoteCertificateHash);
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { remoteCertificateAuthority, remoteCertificateHash });
                    }
                    catch { }
                }
            }
        }
    }
}