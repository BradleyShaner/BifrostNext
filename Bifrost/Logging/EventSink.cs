using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text;
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
        private ITextFormatter _textFormatterClass = new MessageTemplateTextFormatter("{Timestamp:HH:mm:ss.fff} [{Level}] <{Class}> {Message}{Exception}", _formatProvider);

        public static event LogMessage OnLogEvent;

        public HashSet<string> ignoreHashSet = new HashSet<string>();

        public void Emit(LogEvent logEvent)
        {
            if (logEvent == null) throw new ArgumentNullException(nameof(logEvent));

            string logMessage = null;

            if (logEvent.Properties.ContainsKey("Class"))
            {
                LogEventPropertyValue property;
                if (logEvent.Properties.TryGetValue("Class", out property))
                {

                    string ignoreClass = property.ToString();
                    if (ignoreHashSet.Contains(ignoreClass))
                        return;

                    var render = new StringWriter();
                    _textFormatterClass.Format(logEvent, render);
                    logMessage = render.ToString();
                }
            }
            else
            {
                var renderSpace = new StringWriter();
                _textFormatter.Format(logEvent, renderSpace);
                logMessage = renderSpace.ToString();
            }
            //Raise the event on the delegate's thread, should be UI.
            //Necessary otherwise deadlocks ensue and handshake failure due to cross-thread calls..
            RaiseEventOnUIThread(OnLogEvent, logMessage);
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
                    try
                    {
                        syncer.BeginInvoke(d, new object[] { args });
                    }
                    catch { }
                }
            }
        }
    }
}