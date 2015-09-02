using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Service credentials.
    /// </summary>
    public class ServiceCredentials : IKsiServiceSettings
    {
        private readonly string _loginId;
        private readonly byte[] _loginKey;

        /// <summary>
        /// Get login ID.
        /// </summary>
        public string LoginId
        {
            get
            {
                return _loginId;
            }
        }

        /// <summary>
        /// Get login key.
        /// </summary>
        public byte[] LoginKey
        {
            get
            {
                return _loginKey;
            }
        }

        /// <summary>
        /// Get instance ID.
        /// </summary>
        public ulong InstanceId
        {
            get
            {
                return 0;
            }
        }

        /// <summary>
        /// Get message ID.
        /// </summary>
        public ulong MessageId
        {
            get
            {
                return 0;
            }
        }

        /// <summary>
        /// Create service credentials object from login ID and login key as bytes.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="loginKey">login key</param>
        public ServiceCredentials(string loginId, byte[] loginKey)
        {
            _loginId = loginId;
            _loginKey = loginKey;
        }

        /// <summary>
        /// Create servoce credentials object from login ID and login key as string.
        /// </summary>
        /// <param name="loginId">login ID</param>
        /// <param name="loginKey">login key</param>
        public ServiceCredentials(string loginId, string loginKey)
        {
            _loginId = loginId;
            _loginKey = Util.EncodeNullTerminatedUtf8String(loginKey);
        }
    }
}