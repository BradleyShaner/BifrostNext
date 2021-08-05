using BifrostNext.Keys;
using System;
using System.Net;

namespace BifrostNext
{
    public enum AuthState
    {
        Unauthenticated = 0,
        Authenticating,
        Authenticated,
    }

    public enum PrivilegeLevel
    {
        Guest = 0,
        User,
        Moderator,
        Administrator,
        Sysop
    }

    public class ClientData
    {
        public string ClientGuid { get; internal set; }
        public DateTime TimeConnected { get; private set; }
        public static int NextClientId = 0;

        public AuthState AuthenticationState = AuthState.Unauthenticated;
        public int ClientId;
        public KeyData ClientKeys = new KeyData();

        public string ClientName = "";
        public bool Connected;
        public UserConnection Connection;
        public PrivilegeLevel PrivilegeLevel = PrivilegeLevel.Guest;
        public IPEndPoint remoteEndpoint;

        public ClientData(UserConnection userConnection)
        {
            this.Connection = userConnection;
            this.TimeConnected = DateTime.Now;
            this.Connected = true;
            this.ClientGuid = Guid.NewGuid().ToString();
            this.ClientId = NextClientId;
            this.remoteEndpoint = (IPEndPoint)userConnection.TcpClient.Client.RemoteEndPoint;
            NextClientId++;
        }
    }
}