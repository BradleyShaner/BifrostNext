namespace BifrostNext.BifrostLSF
{
    /// <summary>
    /// Describes a common interface that all tunnels should implement.
    /// </summary>
    public interface ITunnel
    {
        bool Closed { get; set; }
        long DataBytesReceived { get; set; }
        long DataBytesSent { get; set; }
        ulong PacketsDropped { get; }
        ulong PacketsReceived { get; }
        long RawBytesReceived { get; set; }
        long RawBytesSent { get; set; }

        void Close();

        byte[] Receive();

        void Send(byte[] data);
    }
}