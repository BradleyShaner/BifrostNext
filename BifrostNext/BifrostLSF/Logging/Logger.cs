using Serilog;
using Serilog.Core;
using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;

namespace BifrostNext.BifrostLSF
{
    public static class LogManager
    {
        public static LoggingLevelSwitch loggingLevel = new LoggingLevelSwitch(Serilog.Events.LogEventLevel.Verbose);
        public static string logPrefix = "";
        public static EventSink LogSink = new EventSink();
        public static string outputLogFile = "";
        public static bool serilogInitialized;
        public static bool showCallingClass = true;

        public static Logger GetCurrentClassLogger()
        {
            if (!serilogInitialized)
            {
                var sink = LogSink;
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Verbose()
                    .MinimumLevel.ControlledBy(loggingLevel)
                    .WriteTo.Sink(sink)
                    .CreateLogger();

                serilogInitialized = true;
            }
            Logger logger = new Logger($"{NameOfCallingClass()}");
            return logger;
        }

        public static void IgnoreLogClass(string ignoreClass) => LogSink.ignoreHashSet.Add("\"" + ignoreClass + "\"");

        public static string NameOfCallingClass()
        {
            string fullName;

            try
            {
                Type declaringType;
                int skipFrames = 2;
                do
                {
                    MethodBase method = new StackFrame(skipFrames, false).GetMethod();
                    declaringType = method.DeclaringType;
                    if (declaringType == null)
                    {
                        return method.Name;
                    }
                    skipFrames++;
                    fullName = declaringType.FullName;
                }
                while (declaringType.Module.Name.Equals("mscorlib.dll", StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                fullName = "UNKNOWN";
            }
            return fullName;
        }

        public static void SetMinimumLogLevel(SerilogLogLevel logLevel)
        {
            LogManager.loggingLevel = new LoggingLevelSwitch((Serilog.Events.LogEventLevel)logLevel);
            serilogInitialized = false;
        }
    }

    public class Logger
    {
        private string className;

        public Logger(string className)
        {
            this.className = className;
        }

        public void Debug(string message, string replace) => Log.ForContext("Class", className).Debug(string.Format(message, replace));

        public void Debug(string message, int replace) => Log.ForContext("Class", className).Debug(string.Format(message, replace));

        public void Debug(string message, ulong length) => Log.ForContext("Class", className).Debug(string.Format(message, length));

        public void Debug(string message) => Log.ForContext("Class", className).Debug(message);

        public void Debug(string message, MessageType? type, byte? subtype) => Log.ForContext("Class", className).Debug(string.Format(message, type.ToString(), subtype));

        public void Debug(MessageType type) => Log.ForContext("Class", className).Debug(type.ToString());

        public void Debug(string message, MessageType type) => Log.ForContext("Class", className).Debug(string.Format(message, type.ToString()));

        public void Debug(string message, IPEndPoint endPoint, string rep) => Log.ForContext("Class", className).Debug(string.Format(message, endPoint.ToString(), rep));

        public void Debug(string message, TimeSpan difference) => Log.ForContext("Class", className).Debug(string.Format(message, difference.ToString()));

        public void Debug(string message, string rep1, string rep2, string rep3) => Log.ForContext("Class", className).Debug(string.Format(message, rep1, rep2, rep3));

        public void Error(Exception ex) => Log.ForContext("Class", className).Error(ex, "");

        public void Error(string message, string replace) => Log.ForContext("Class", className).Error(string.Format(message, replace));

        public void Error(Exception ex, string message) => Log.ForContext("Class", className).Error(ex, message);

        public void Error(string message) => Log.ForContext("Class", className).Error(message);

        public void Info(string message, TimeSpan difference) => Log.ForContext("Class", className).Information(string.Format(message, difference.ToString()));

        public void Info(string message, MessageType type) => Log.ForContext("Class", className).Information(string.Format(message, type.ToString()));

        public void Info(string message, string replace) => Log.ForContext("Class", className).Information(string.Format(message, message));

        public void Info(MessageType type) => Log.ForContext("Class", className).Information(type.ToString());

        public void Info(string message, int replace) => Log.ForContext("Class", className).Information(string.Format(message, replace));

        public void Info(string message) => Log.ForContext("Class", className).Information(message);

        public void Info(string message, IPEndPoint endPoint, string rep) => Log.ForContext("Class", className).Information(string.Format(message, endPoint.ToString(), rep));

        public void Info(string message, MessageType? type, byte? subtype) => Log.ForContext("Class", className).Information(string.Format(message, type.ToString(), subtype));

        public void Info(string message, string rep1, string rep2, string rep3) => Log.ForContext("Class", className).Information(string.Format(message, rep1, rep2, rep3));

        public void Trace(string message, string str) => Log.ForContext("Class", className).Verbose(string.Format(message, str));

        public void Trace(string message, int replace) => Log.ForContext("Class", className).Verbose(string.Format(message, replace));

        public void Trace(string message) => Log.ForContext("Class", className).Verbose(message);

        public void Trace(Exception ex) => Log.ForContext("Class", className).Verbose(ex.Message);

        public void Warn(string message, ushort replace) => Log.ForContext("Class", className).Warning(string.Format(message, replace));

        public void Warn(string message, string rep1, string rep2) => Log.ForContext("Class", className).Warning(string.Format(message, rep1, rep2));

        public void Warn(string message, MessageType type, string replace) => Log.ForContext("Class", className).Warning(string.Format(message, type.ToString(), replace));

        public void Warn(string message, int replace) => Log.ForContext("Class", className).Warning(string.Format(message, replace));

        public void Warn(Exception ex) => Log.ForContext("Class", className).Warning(ex, "");

        public void Warn(string message, string replace) => Log.ForContext("Class", className).Warning(string.Format(message, replace));

        public void Warn(string message) => Log.ForContext("Class", className).Warning(message);

        public void Warn(string message, string rep1, string rep2, string rep3, string rep4) => Log.ForContext("Class", className).Warning(string.Format(message, rep1, rep2, rep3, rep4));

        public void Warn(string message, string rep1, string rep2, string rep3, int rep4) => Log.ForContext("Class", className).Warning(string.Format(message, rep1, rep2, rep3, rep4));

        public void Warn(string message, string rep1, string rep2, int rep3) => Log.ForContext("Class", className).Warning(string.Format(message, rep1, rep2, rep3));

        public void Warn(string message, MessageType type, byte replace) => Log.ForContext("Class", className).Warning(string.Format(message, type.ToString(), replace));
    }
}