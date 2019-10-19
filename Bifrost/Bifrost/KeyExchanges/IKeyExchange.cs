namespace Bifrost.KeyExchanges
{
    public interface IKeyExchange
    {
        string HumanName { get; }
        ushort KeyExchangeIdentifier { get; }

        byte[] FinalizeKeyExchange(byte[] peer_pk);

        byte[] GetPublicKey();

        void Initialize();
    }
}