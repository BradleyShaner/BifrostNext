using System;
using System.Net.Sockets;

namespace BifrostNext.BifrostLSF
{
    /// <summary>
    /// Tunnels Bifrost data over very simple TCP. 4 bytes of overhead per message.
    /// </summary>
    public class TcpTunnel : ITunnel
    {
        public Logger Log = LogManager.GetCurrentClassLogger();

        public bool Closed { get; set; }
        public TcpClient Connection { get; set; }
        public NetworkStream NetworkStream { get; set; }

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

        /// <summary>
        /// Construct a new TcpTunnel with the provided parameters.
        /// </summary>
        /// <param name="client">The TcpClient to use.</param>
        /// <param name="prepare">Initializes the internal streams. Set to false if the TcpClient hasn't been connected yet, and then call InitializeStreams when it's connected.</param>
        public TcpTunnel(TcpClient client, bool prepare = true)
        {
            Connection = client;

            if (prepare)
                InitializeStreams();
        }

        /// <summary>
        /// Closes the TcpTunnel. This stuff is a bit tricky(yes, trickier than the rest of the project!), and hasn't been tested a lot yet, so YMMV.
        /// </summary>
        public void Close()
        {
            NetworkStream.Close(100);
            Connection.Close();
            Closed = true;
        }

        /// <summary>
        /// Initializes the internal streams used for communication.
        /// </summary>
        public void InitializeStreams()
        {
            NetworkStream = Connection.GetStream();
        }

        /// <summary>
        /// Receives a single data chunk.
        /// </summary>
        /// <returns>The received chunk of data.</returns>
        public byte[] Receive()
        {
            try
            {
                uint len = NetworkStream.ReadUInt();

                RawBytesReceived += len + 4;
                DataBytesReceived += len;

                return NetworkStream.ReadSafe(len);
            }
            catch (Exception ex)
            {
                Log.Trace(ex);
                Close();
                return new byte[0];
            }
        }

        /// <summary>
        /// Sends raw data over the TcpTunnel.
        /// </summary>
        /// <param name="data">The data to be sent.</param>
        public void Send(byte[] data)
        {
            try
            {
                NetworkStream.WriteUInt((uint)data.Length);
                NetworkStream.Write(data, 0, data.Length);

                RawBytesSent += data.Length + 4;
                DataBytesSent += data.Length;
            }
            catch (Exception ex)
            {
                Log.Trace(ex);
                Close();
            }
        }
    }
}