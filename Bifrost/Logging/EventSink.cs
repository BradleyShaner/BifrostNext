using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting;
using Serilog.Formatting.Display;
using System;
using System.Collections.Generic;
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
        public HashSet<string> ignoreHashSet = new HashSet<string>();
        private readonly static IFormatProvider _formatProvider = null;

        private ITextFormatter _textFormatter = new MessageTemplateTextFormatter("{Timestamp:HH:mm:ss.fff} [{Level}] {Message}{Exception}", _formatProvider);
        private ITextFormatter _textFormatterClass = new MessageTemplateTextFormatter("{Timestamp:HH:mm:ss.fff} [{Level}] <{Class}> {Message}{Exception}", _formatProvider);

        public static event LogMessage OnLogEvent;

        public void Emit(LogEvent logEvent)
        {
            if (logEvent == null) throw new ArgumentNullException(nameof(logEvent));

            string logMessage = null;

            if (logEvent.Properties.ContainsKey("Class"))
            {
                LogEventPropertyValue property;
                if (logEvent.Properties.TryGetValue("Class", out property))
                {
                    var render = new StringWriter();
                    _textFormatterClass.Format(logEvent, render);
                    logMessage = LogManager.logPrefix + render.ToString();

                    string ignoreClass = property.ToString();
                    if (ignoreHashSet.Contains(ignoreClass))
                    {
                        if (!String.IsNullOrWhiteSpace(LogManager.outputLogFile))
                            File.AppendAllText(LogManager.outputLogFile, logMessage);
                        return;
                    }
                }
            }
            else
            {
                var renderSpace = new StringWriter();
                _textFormatter.Format(logEvent, renderSpace);
                logMessage = LogManager.logPrefix + renderSpace.ToString();
            }

            if (!String.IsNullOrWhiteSpace(LogManager.outputLogFile))
                File.AppendAllText(LogManager.outputLogFile, logMessage);

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