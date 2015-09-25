namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service settings interface.
    /// </summary>
    public interface IKsiServiceSettings
    {
        /// <summary>
        ///     Login ID.
        /// </summary>
        string LoginId { get; }

        /// <summary>
        ///     Login key.
        /// </summary>
        byte[] LoginKey { get; }

        /// <summary>
        ///     Instance ID.
        /// </summary>
        ulong InstanceId { get; }

        /// <summary>
        ///     Message ID.
        /// </summary>
        ulong MessageId { get; }
    }
}