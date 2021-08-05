using System;
using System.Collections.Generic;

namespace BifrostNext
{
    public class Delegates
    {
        public delegate void ClientConnectionState(Client client, bool Connected);

        // Client
        public delegate void ClientDataReceived(Client client, Dictionary<string, byte[]> Store);

        public delegate Delegate LogMessage(string log);

        public delegate void ServerDataReceived(ClientData client, Dictionary<string, byte[]> Store);

        // Server
        public delegate void UserConnected(ClientData client);

        public delegate void UserDisconnected(ClientData client);
    }
}