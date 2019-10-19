using System.Collections.Concurrent;

namespace BifrostLSF
{
    public interface IListener
    {
        BlockingCollection<ITunnel> Queue { get; set; }

        ITunnel Accept();

        void Start();

        void Stop();
    }
}