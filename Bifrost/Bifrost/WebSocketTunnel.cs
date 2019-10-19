using Bifrost.WebSockets;
using System;
using System.Net;
using System.Net.Sockets;

namespace BifrostLSF
{
    public class WebSocketTunnel : ITunnel
    {
        private Logger Log = LogManager.GetCurrentClassLogger();

        public bool Closed
        {
            get
            {
                return Connection.Closed;
            }
            set
            {
            }
        }

        public WebSocketConnection Connection { get; set; }

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

        public ulong PacketsDropped { get => 0; }
        public ulong PacketsReceived { get => 0; }

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

        public WebSocketTunnel(TcpClient client, string host, string origin, bool server)
        {
            if (server)
            {
                var conn = new ServerConnection(client);
                conn.PerformHandshake();

                Connection = conn;
            }
            else
            {
                var conn = new ClientConnection(client);
                conn.PerformHandshake(host, origin);

                Connection = conn;
            }

            Connection.StartThreads();
        }

        public void Close()
        {
            Connection.Close();
        }

        public byte[] Receive()
        {
            try
            {
                var msg = Connection.Receive();
                RawBytesReceived += msg.Length;

                return msg;
            }
            catch (Exception ex)
            {
                Log.Error("WebSocket connection broken, closing tunnel");
                Log.Error(ex);
                Close();

                return null;
            }
        }

        public void Send(byte[] data)
        {
            Connection.SendBinary(data);
            RawBytesSent += data.Length;
        }

        public override string ToString()
        {
            try
            {
                return string.Format("WebSocket tunnel from {0}", (IPEndPoint)Connection?.Client?.Client?.RemoteEndPoint);
            }
            catch (Exception ex)
            {
                return "WebSocket tunnel, unknown origin";
            }
        }
    }
}