using System;

namespace Guardtime.KSI.Service
{
    public class KsiServiceSettings : IKsiServiceSettings
    {
        private string _loginId;
        private byte[] _loginKey;
        private ulong _instanceId;
        private ulong _messageId;

        public ulong InstanceId
        {
            get
            {
                return _instanceId;
            }
        }

        public string LoginId
        {
            get
            {
                return _loginId;
            }
        }

        public byte[] LoginKey
        {
            get
            {
                return _loginKey;
            }
        }

        public ulong MessageId
        {
            get
            {
                return _messageId;
            }
        }

        public KsiServiceSettings(string loginId, byte[] loginKey)
        {
            _loginId = loginId;
            _loginKey = loginKey;
            _instanceId = 0;
            _messageId = 0;
        }
    }
}