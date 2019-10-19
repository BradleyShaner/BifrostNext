using System.Collections.Concurrent;

namespace Bifrost
{
    public interface IListener
    {
        BlockingCollection<ITunnel> Queue { get; set; }

        ITunnel Accept();

        void Start();

        void Stop();
    }
}