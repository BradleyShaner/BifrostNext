using System.Collections.Concurrent;
using System.Net.Sockets;

namespace BifrostLSF
{
    public class HttpListener : IListener
    {
        public bool Compression { get; set; }
        public TcpListener Listener { get; set; }
        public BlockingCollection<ITunnel> Queue { get; set; }
        public bool Server { get; set; }

        public ITunnel Accept()
        {
            return new HttpTunnel(Listener.AcceptTcpClient(), Server, Compression);
        }

        public void Start()
        {
            Listener.Start();
        }

        public void Stop()
        {
            Listener.Stop();
        }
    }
}