using Serilog;
using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;

namespace Bifrost
{
    public static class LogManager
    {
        public static EventSink LogSink = new EventSink();
        public static bool serilogInitialized;

        public static Logger GetCurrentClassLogger()
        {
            if (!serilogInitialized)
            {
                var sink = LogSink;
                Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.Sink(sink)
                    .CreateLogger();
            }
            Logger logger = new Logger($"<{NameOfCallingClass()}>");
            return logger;
        }

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
    }

    public class Logger
    {
        private string className;

        public Logger(string className)
        {
            this.className = className;
        }

        public void Debug(string message, string replace) => Log.Debug($"{className} " + string.Format(message, replace));

        public void Debug(string message, int replace) => Log.Debug($"{className} " + string.Format(message, replace));

        public void Debug(string message, ulong length) => Log.Debug($"{className} " + string.Format(message, length));

        public void Debug(string message) => Log.Debug($"{className} " + message);

        public void Error(Exception ex) => Log.Error(ex, $"{className} ");

        public void Error(string message, string replace) => Log.Error($"{className} " + string.Format(message, replace));

        public void Error(string message) => Log.Error($"{className} " + message);

        public void Info(string message, TimeSpan difference) => Log.Information($"{className} " + string.Format(message, difference.ToString()));

        public void Info(string message, MessageType type) => Log.Information($"{className} " + string.Format(message, type.ToString()));

        public void Info(string message, string replace) => Log.Information($"{className} " + string.Format(message, message));

        public void Info(MessageType type) => Log.Information($"{className} " + type.ToString());

        public void Info(string message, int replace) => Log.Information($"{className} " + string.Format(message, replace));

        public void Info(string message) => Log.Information($"{className} " + message);

        public void Info(string message, IPEndPoint endPoint, string rep) => Log.Information($"{className} " + string.Format(message, endPoint.ToString(), rep));

        public void Info(string message, MessageType? type, byte? subtype) => Log.Information($"{className} " + string.Format(message, type.ToString(), subtype));

        public void Info(string message, string rep1, string rep2, string rep3) => Log.Information($"{className} " + string.Format(message, rep1, rep2, rep3));

        public void Trace(string message, string str) => Log.Verbose($"{className} " + string.Format(message, str));

        public void Trace(string message, int replace) => Log.Verbose($"{className} " + string.Format(message, replace));

        public void Trace(string message) => Log.Verbose($"{className} " + message);

        public void Warn(string message, ushort replace) => Log.Warning($"{className} " + string.Format(message, replace));

        public void Warn(string message, string rep1, string rep2) => Log.Warning($"{className} " + string.Format(message, rep1, rep2));

        public void Warn(string message, MessageType type, string replace) => Log.Warning($"{className} " + string.Format(message, type.ToString(), replace));

        public void Warn(string message, int replace) => Log.Warning($"{className} " + string.Format(message, replace));

        public void Warn(Exception ex) => Log.Warning(ex, $"{className} ");

        public void Warn(string message, string replace) => Log.Warning($"{className} " + string.Format(message, replace));

        public void Warn(string message) => Log.Warning($"{className} " + message);

        public void Warn(string message, string rep1, string rep2, string rep3, string rep4) => Log.Warning($"{className} " + string.Format(message, rep1, rep2, rep3, rep4));

        public void Warn(string message, string rep1, string rep2, string rep3, int rep4) => Log.Warning($"{className} " + string.Format(message, rep1, rep2, rep3, rep4));

        public void Warn(string message, string rep1, string rep2, int rep3) => Log.Warning($"{className} " + string.Format(message, rep1, rep2, rep3));

        public void Warn(string message, MessageType type, byte replace) => Log.Warning($"{className} " + string.Format(message, type.ToString(), replace));
    }
}