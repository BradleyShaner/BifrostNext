using System.Net;

namespace BifrostNext.BifrostLSF.Udp
{
    public class UdpTunnel : ITunnel
    {
        public static int SourcePortEnd = 20200;
        public static int SourcePortStart = 10100;
        private static int SourcePort = 10100;
        private Logger Log = LogManager.GetCurrentClassLogger();
        public bool Closed { get; set; }
        internal UdpSession Session { get; set; }
        private IPEndPoint EndPoint { get; set; }

        #region Statistics

        public long DataBytesReceived { get; set; }
        public long DataBytesSent { get; set; }

        public double OverheadReceived
        {
            get
            {
                return (double)ProtocolBytesReceived / (double)RawBytesReceived;
            }
        }

        public double OverheadSent
        {
            get
            {
                return (double)ProtocolBytesSent / (double)RawBytesSent;
            }
        }

        public ulong PacketsDropped { get => Session.DroppedFragments; }
        public ulong PacketsReceived { get => Session.ReceivedFragments; }

        public long ProtocolBytesReceived
        {
            get
            {
                return RawBytesReceived - DataBytesReceived;
            }
        }

        public long ProtocolBytesSent
        {
            get
            {
                return RawBytesSent - DataBytesSent;
            }
        }

        public long RawBytesReceived { get; set; }
        public long RawBytesSent { get; set; }

        #endregion Statistics

        public UdpTunnel(IPAddress addr, int port, int mtu = 0)
        {
            SourcePort++;

            if (SourcePort > SourcePortEnd)
                SourcePort = SourcePortStart;

            EndPoint = new IPEndPoint(addr, port);

            UdpListener temp_listener = new UdpListener(IPAddress.Any, SourcePort, false);
            temp_listener.Start();

            Session = new UdpSession(temp_listener.Socket, temp_listener, EndPoint);
            Session.ForceMTU = mtu;
            temp_listener.Sessions[UdpListener.EndPointToTuple(EndPoint)] = Session;

            Session.Connect();
        }

        public UdpTunnel(IPEndPoint ep, int mtu = 0) :
            this(ep.Address, ep.Port, mtu)
        {
        }

        internal UdpTunnel(UdpSession session)
        {
            Session = session;
        }

        public void Close()
        {
            Closed = true;
            Session.ReceiveQueue.Add(new byte[0]); // unblock Receive()

            if (!Session.Listener.QueueConnections)
                Session.Listener.Stop();

            Session.Listener.Close(Session);
        }

        public byte[] Receive()
        {
            var ret = Session.Receive();
            RawBytesReceived += ret.Length;

            return ret;
        }

        public void Send(byte[] data)
        {
            RawBytesSent += data.Length;
            Session.Send(data);
        }

        public override string ToString()
        {
            return string.Format("UDP tunnel on {0}", EndPoint);
        }
    }
}