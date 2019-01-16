using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;
using System;
using System.ComponentModel;
using System.IO;
using static Bifrost.Delegates;

namespace Bifrost
{
    public class Delegates
    {
        public delegate System.Delegate LogMessage(string log);
    }

    public class EventSink : ILogEventSink
    {
        private readonly static IFormatProvider _formatProvider = null;

        private ITextFormatter _textFormatter = new MessageTemplateTextFormatter("{Timestamp:HH:mm:ss.fff} [{Level}] {Message}{Exception}", _formatProvider);

        public static event LogMessage OnLogEvent;

        public void Emit(LogEvent logEvent)
        {
            if (logEvent == null) throw new ArgumentNullException(nameof(logEvent));
            var renderSpace = new StringWriter();
            _textFormatter.Format(logEvent, renderSpace);

            //Raise the event on the delegate's thread, should be UI.
            //Necessary otherwise deadlocks ensue and handshake failure due to cross-thread calls..
            RaiseEventOnUIThread(OnLogEvent, renderSpace.ToString());
        }

        private void RaiseEventOnUIThread(Delegate theEvent, string args)
        {
            if (theEvent == null)
                return;

            foreach (Delegate d in theEvent.GetInvocationList())
            {
                ISynchronizeInvoke syncer = d.Target as ISynchronizeInvoke;
                if (syncer == null)
                {
                    d.DynamicInvoke(args);
                }
                else
                {
                    syncer.BeginInvoke(d, new object[] { args });
                }
            }
        }
    }
}