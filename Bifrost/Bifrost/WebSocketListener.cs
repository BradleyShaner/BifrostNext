using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace BifrostLSF
{
    public class WebSocketListener : IListener
    {
        private ManualResetEvent _stopped = new ManualResetEvent(false);
        private Logger Log = LogManager.GetCurrentClassLogger();

        public string Host { get; set; }
        public TcpListener Listener { get; set; }

        public string Origin { get; set; }
        public BlockingCollection<ITunnel> Queue { get; set; }
        public bool Server { get; set; }

        public WebSocketListener(IPEndPoint ep, string host, string origin, bool server = true)
        {
            Listener = new TcpListener(ep);

            Host = host;
            Origin = origin;
            Server = server;

            Queue = new BlockingCollection<ITunnel>();

            Utilities.StartThread(AcceptThread);
        }

        public ITunnel Accept()
        {
            return Queue.Take();
        }

        public void AcceptThread()
        {
            while (true)
            {
                while (!_stopped.WaitOne(0))
                {
                    try
                    {
                        Queue.Add(new WebSocketTunnel(Listener.AcceptTcpClient(), Host, Origin, Server));
                    }
                    catch (Exception ex)
                    {
                        if (_stopped.WaitOne(0))
                            break;

                        Log.Error(ex);
                    }
                }

                Thread.Sleep(100);
            }
        }

        public void Start()
        {
            _stopped.Reset();
            Listener.Start();
        }

        public void Stop()
        {
            _stopped.Set();
            Listener.Stop();
        }
    }
}