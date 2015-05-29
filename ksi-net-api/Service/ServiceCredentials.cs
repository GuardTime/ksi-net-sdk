namespace Guardtime.KSI.Service
{
    public class ServiceCredentials
    {
        private readonly string _loginId;
        private readonly byte[] _loginKey;

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

        public ServiceCredentials(string loginId, byte[] loginKey)
        {
            _loginId = loginId;
            _loginKey = loginKey;
        }

        public ServiceCredentials(string loginId, string loginKey)
        {
            _loginId = loginId;
            _loginKey = Util.Util.EncodeNullTerminatedUtf8String(loginKey);
        }
    }
}