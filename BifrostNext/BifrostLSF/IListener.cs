using System.Collections.Concurrent;

namespace BifrostNext.BifrostLSF
{
    public interface IListener
    {
        BlockingCollection<ITunnel> Queue { get; set; }

        ITunnel Accept();

        void Start();

        void Stop();
    }
}