using BifrostNext.BifrostLSF;
using BifrostNext.Keys;
using BifrostNext.Messages;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static BifrostNext.Delegates;

namespace BifrostNext
{
    public class Server
    {
        public bool IsRunning { get; private set; }
        public int MaxConnections = 100;
        public bool NoAuthentication = false;
        public bool RememberCertificates = false;
        private readonly object _UserListLock = new object();
        private List<ClientData> Clients = new List<ClientData>();
        private TcpListener listener = null;
        private Logger logger = LogManager.GetCurrentClassLogger();

        private CancellationToken serverCancellationToken;

        private CancellationTokenSource serverCancellationTokenSource = new CancellationTokenSource();

        public event LogMessage OnLogEvent;

        public event ServerDataReceived OnServerDataReceived;

        public event UserConnected OnUserConnected;

        public event UserDisconnected OnUserDisconnected;

        public Server(int maxConnections = 100)
        {
            LogManager.SetMinimumLogLevel(SerilogLogLevel.Verbose);
            EventSink.OnLogEvent += EventSink_OnLogEvent;

            CertManager.GenerateCertificateAuthority();

            MaxConnections = maxConnections;
        }

        public void BroadcastMessage(Dictionary<string, byte[]> Store, AuthState minimumAuthState = AuthState.Authenticated, ClientData skipUser = null)
        {
            Message msg = new Message(MessageType.Data, 0x01);
            msg.Store = Store;

            lock (_UserListLock)
            {
                foreach (var user in Clients)
                {
                    try
                    {
                        if (skipUser != null && user == skipUser)
                            continue;

                        if (user.AuthenticationState >= minimumAuthState)
                            user.Connection.ServerLink.SendMessage(msg);
                    }
                    catch (Exception ex)
                    {
                        logger.Trace(ex.Message, "Server BroadcastMessage: " + user.ClientName != string.Empty ? user.ClientGuid : user.ClientName);
                    }
                }
            }
        }

        public void BroadcastMessage(IMessage msg, AuthState minimumAuthState = AuthState.Authenticated, ClientData skipUser = null)
        {
            string serialized = JsonConvert.SerializeObject(msg, Formatting.None);

            Type t = msg.GetType();

            Message message = new Message(MessageType.Data, 0x01);
            message.Store["type"] = Encoding.UTF8.GetBytes(t.Name);
            message.Store["message"] = Utilities.Compress(Encoding.UTF8.GetBytes(serialized));

            lock (_UserListLock)
            {
                foreach (var user in Clients)
                {
                    try
                    {
                        if (skipUser != null && user == skipUser)
                            continue;

                        if (user.AuthenticationState >= minimumAuthState)
                            user.Connection.ServerLink.SendMessage(message);
                    }
                    catch (Exception ex)
                    {
                        logger.Trace(ex.Message, "Server BroadcastMessage: " + user.ClientName != string.Empty ? user.ClientGuid : user.ClientName);
                    }
                }
            }
        }

        public void BroadcastMessage(IMessage msg, PrivilegeLevel minimumPrivLevel = PrivilegeLevel.Administrator, ClientData skipUser = null)
        {
            string serialized = JsonConvert.SerializeObject(msg, Formatting.None);

            Type t = msg.GetType();

            Message message = new Message(MessageType.Data, 0x01);
            message.Store["type"] = Encoding.UTF8.GetBytes(t.Name);
            message.Store["message"] = Utilities.Compress(Encoding.UTF8.GetBytes(serialized));

            lock (_UserListLock)
            {
                foreach (var user in Clients)
                {
                    try
                    {
                        if (skipUser != null && user == skipUser)
                            continue;

                        if (user.PrivilegeLevel >= minimumPrivLevel)
                            user.Connection.ServerLink.SendMessage(message);
                    }
                    catch (Exception ex)
                    {
                        logger.Trace(ex.Message, "Server BroadcastMessage: " + user.ClientName != string.Empty ? user.ClientGuid : user.ClientName);
                    }
                }
            }
        }

        public ClientData GetClientFromLink(ServerLink serverLink)
        {
            lock (_UserListLock)
            {
                foreach (var user in Clients)
                {
                    if (user.Connection.ServerLink == serverLink)
                    {
                        logger.Trace("GetClientFromLink found: " + user.ClientId);
                        return user;
                    }
                }
            }
            return null;
        }

        public ClientData GetClientFromLink(EncryptedLink encryptedLink)
        {
            lock (_UserListLock)
            {
                foreach (var user in Clients)
                {
                    if (user.Connection.ServerLink.GetEncryptedLink() == encryptedLink)
                    {
                        logger.Trace("GetClientFromLink found: " + user.ClientId);
                        return user;
                    }
                }
            }
            return null;
        }

        public void IgnoreLogClass(string ignoredClass)
        {
            LogManager.IgnoreLogClass(ignoredClass);
        }

        public bool IsConnectionTrusted(ClientData client)
        {
            return client.Connection.ServerLink.TrustedCertificateUsed;
        }

        public bool SendMessage(Dictionary<string, byte[]> Store, UserConnection user)
        {
            Message msg = new Message(MessageType.Data, 0x01);
            msg.Store = Store;

            try
            {
                user.ServerLink.SendMessage(msg);
            }
            catch (Exception ex)
            {
                logger.Trace(ex.Message, "Server SendMessage");
                return false;
            }
            return true;
        }

        public bool SendMessage(IMessage msg, UserConnection user)
        {
            string serialized = JsonConvert.SerializeObject(msg, Formatting.None);

            Type t = msg.GetType();

            Message message = new Message(MessageType.Data, 0x01);
            message.Store["type"] = Encoding.UTF8.GetBytes(t.Name);
            message.Store["message"] = Utilities.Compress(Encoding.UTF8.GetBytes(serialized));

            try
            {
                user.ServerLink.SendMessage(message);
            }
            catch (Exception ex)
            {
                logger.Trace(ex.Message, "Server SendMessage");
                return false;
            }
            return true;
        }

        public void SetLogLevel(SerilogLogLevel logLevel)
        {
            LogManager.SetMinimumLogLevel(logLevel);
        }

        public bool Start(int listenPort, int keysToPreCalculate = 0)
        {
            serverCancellationToken = serverCancellationTokenSource.Token;
            try
            {
                this.listener = new TcpListener(IPAddress.Any, listenPort);
                this.listener.Start();
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Unable to start server!");
                return false;
            }

            if (keysToPreCalculate == 0)
            {
                if (MaxConnections >= 10)
                    keysToPreCalculate = MaxConnections / 10;
                else
                    keysToPreCalculate = 1;
            }

            Task.Factory.StartNew(() => KeyManager.MonitorKeyGeneration(serverCancellationToken, keysToPreCalculate),
                    serverCancellationToken,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);

            Task listener = Task.Factory.StartNew(() => ThreadedServerStart(this.listener, serverCancellationToken),
                serverCancellationToken,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);

            IsRunning = true;
            logger.Info($"Listening for clients on port {listenPort}..");
            return true;
        }

        public void Stop()
        {
            if (serverCancellationToken.CanBeCanceled)
                serverCancellationTokenSource.Cancel();

            IsRunning = false;

            if (listener != null)
                listener.Stop();
            else
                listener = null;

            lock (_UserListLock)
            {
                for (int i = Clients.Count - 1; i >= 0; i--)
                {
                    Clients[i].Connection.ServerLink.Close();
                    //users[i].tcpTunnel.Close();
                    //users[i].tcpClient.Close();
                    //users[i].clientThread.Abort();
                }
            }

            logger.Info($"Server is stopped..");
        }

        public void TrustClientCertificate(ClientData client, bool trusted)
        {
            lock (_UserListLock)
            {
                client.Connection.ServerLink.SetCertificateAuthorityTrust(trusted);
            }
        }

        private void CleanupClient(ClientData client)
        {
            try
            {
                lock (_UserListLock)
                {
                    if (client.Connected)
                        client.Connection.ServerLink.Close();

                    Clients.Remove(client);
                }
            }
            finally { }
        }

        private Delegate EventSink_OnLogEvent(string log)
        {
            Utilities.RaiseEventOnUIThread(OnLogEvent, log);
            return null;
        }

        private void Link_OnDataReceived(EncryptedLink link, Dictionary<string, byte[]> Store)
        {
            ClientData clientData = GetClientFromLink(link);

            if (clientData == null)
            {
                logger.Warn($"clientData null");
                return;
            }

            // If the store contains a Message type..
            if (Store.ContainsKey("type") && Handler.GetServerMessageType(Encoding.UTF8.GetString(Store["type"])) != null)
            {
                logger.Debug($"Incoming compressed packet: {Store["message"].Length} bytes");
                IMessage message = Handler.ConvertServerPacketToMessage(Store["type"], Utilities.Decompress(Store["message"]));
                Handler.HandleServerMessage(clientData, message);
            }
            else
            {
                logger.Warn("Unknown MessageType sent from Client: " + Encoding.UTF8.GetString(Store["type"]));
                Utilities.RaiseEventOnUIThread(OnServerDataReceived, clientData, Store);
            }
        }

        private void Link_OnLinkClosed(EncryptedLink link)
        {
            ClientData cd = GetClientFromLink(link);

            if (cd != null)
            {
                cd.Connected = false;
                Utilities.RaiseEventOnUIThread(OnUserDisconnected, cd);
                CleanupClient(cd);
            }
        }

        private void ProcessClient(object argument)
        {
            TcpClient client = (TcpClient)argument;

            logger.Trace($"Client socket accepted..");
            TcpTunnel tunnel = new TcpTunnel(client);
            logger.Trace($"Client tunnel created..");
            ServerLink link = new ServerLink(tunnel);
            logger.Trace($"Client link created..");

            link.RememberRemoteCertAuthority = RememberCertificates;
            link.NoAuthentication = NoAuthentication;

            //link.RememberPeerKeys = true;

            // Get a key from the precomputed keys list
            string ca, priv;
            byte[] sign;

            (ca, priv, sign) = KeyManager.GetNextAvailableKeys();

            if (String.IsNullOrEmpty(ca) || String.IsNullOrEmpty(priv) || sign.Length == 0)
            {
                logger.Error("GetNextAvailableKeys returned empty data!");
                link.Close();
                return;
            }

            logger.Trace($"Passing certificates into Bifrost..");
            link.LoadCertificatesNonBase64(ca, priv, sign);

            link.OnDataReceived += Link_OnDataReceived;
            link.OnLinkClosed += Link_OnLinkClosed;

            var connection = new UserConnection(client, serverLink: link);
            var user = new ClientData(connection);
            user.ClientKeys.ServerCertificateAuthority = ca;
            user.ClientKeys.PrivateKey = priv;
            user.ClientKeys.SignKey = sign;

            logger.Debug($"Performing handshake with client..");
            var result = link.PerformHandshake();

            if (result.Type == HandshakeResultType.Successful)
            {
                lock (_UserListLock)
                {
                    if (Clients.Count + 1 > MaxConnections)
                    {
                        link.Close();
                        return;
                    }
                    Clients.Add(user);
                }

                logger.Debug($"Handshake was a success!");
                Utilities.RaiseEventOnUIThread(OnUserConnected, user);
            }
            else
            {
                logger.Info($"Handshake failure: {result.Type}");
                link.Close();
            }
        }

        private void ThreadedServerStart(TcpListener listener, CancellationToken token)
        {
            logger.Debug($"Threaded listen server started..");
            while (!token.IsCancellationRequested)
            {
                while (IsRunning && !listener.Pending())
                    Thread.Sleep(1);

                while (Clients.Count >= MaxConnections)
                {
                    Thread.Sleep(10);
                    continue;
                }

                if (!IsRunning)
                    return;

                TcpClient client = new TcpClient();

                client = listener.AcceptTcpClient();

                Task task = Task.Factory.StartNew(() => ProcessClient(client),
                    serverCancellationToken,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);

                //task.ContinueWith( taskResult => logger.Debug($"ProcessClient task {task.Id} has finished."));
            }
        }
    }
}