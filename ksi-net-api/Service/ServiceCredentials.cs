using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Service credentials.
    /// </summary>
    public class ServiceCredentials : IKsiServiceSettings
    {
        /// <summary>
        ///     Create service credentials object from login ID and login key as bytes.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="loginKey">login key</param>
        public ServiceCredentials(string loginId, byte[] loginKey)
        {
            LoginId = loginId;
            LoginKey = loginKey;
        }

        /// <summary>
        ///     Create servoce credentials object from login ID and login key as string.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="loginKey">login key</param>
        public ServiceCredentials(string loginId, string loginKey)
        {
            LoginId = loginId;
            LoginKey = Util.EncodeNullTerminatedUtf8String(loginKey);
        }

        /// <summary>
        ///     Get login ID.
        /// </summary>
        public string LoginId { get; }

        /// <summary>
        ///     Get login key.
        /// </summary>
        public byte[] LoginKey { get; }

        /// <summary>
        ///     Get instance ID.
        /// </summary>
        public ulong InstanceId => 0;

        /// <summary>
        ///     Get message ID.
        /// </summary>
        public ulong MessageId => 0;
    }
}