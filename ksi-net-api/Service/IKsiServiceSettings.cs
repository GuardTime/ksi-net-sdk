namespace Guardtime.KSI.Service
{
    public interface IKsiServiceSettings
    {
        string LoginId { get; }
        byte[] LoginKey { get; }
        ulong InstanceId { get; }
        ulong MessageId { get; }
    }
}