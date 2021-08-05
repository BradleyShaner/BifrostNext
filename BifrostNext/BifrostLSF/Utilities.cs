﻿using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;

namespace BifrostNext.BifrostLSF
{
    public class Utilities
    {
        private static Logger Log = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// Returns the Bifrost version as patched by AppVeyor.
        /// </summary>
        /// <returns>The Bifrost build version.</returns>
        public static string GetVersion()
        {
            string version = FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).ProductVersion;

            // truncate git hash to 8 chars for readability
            var parts = version.Split('-');

            if (parts.Length > 1)
            {
                parts[parts.Length - 1] = parts[parts.Length - 1].Substring(0, 8);
                version = string.Join("-", parts);
            }

            version = "\"" + version + "\"";

            if (parts.Length <= 1)
                version += " (unrecognized version, not an AppVeyor build)";

            return version;
        }

        /// <summary>
        /// Logs the Bifrost version as patched by AppVeyor.
        /// </summary>
        public static void LogVersion()
        {
            Log.Info("Bifrost version {0}", GetVersion());
        }

        /// <summary>
        /// Starts a new thread with the given delegate. Useful for not getting bottlenecked by ThreadPool.
        /// </summary>
        /// <param name="action">The delegate to execute.</param>
        /// <returns>The created thread.</returns>
        public static Thread StartThread(Action action)
        {
            Thread thr = new Thread(() => action());
            thr.Start();
            return thr;
        }

    }
}