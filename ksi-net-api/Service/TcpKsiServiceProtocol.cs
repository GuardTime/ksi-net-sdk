using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     TCP KSI service protocol.
    /// </summary>
    public class TcpKsiServiceProtocol : IKsiSigningServiceProtocol
    {
        private readonly int _requestTimeOut = 2000;
        private readonly int _bufferSize = 8192;
        private readonly string _signingUrl;
        private readonly int _signingPort;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        /// <summary>
        ///     Create TCP KSI service protocol with given url-s
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="signingPort">signing port</param>
        public TcpKsiServiceProtocol(string signingUrl, int signingPort)
        {
            _signingUrl = signingUrl;
            _signingPort = signingPort;
        }

        /// <summary>
        ///     Create TCP KSI service protocol with given url-s and request timeout
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="signingPort">signing port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        public TcpKsiServiceProtocol(string signingUrl, int signingPort, int requestTimeout) : this(signingUrl, signingPort)
        {
            if (requestTimeout < 0)
            {
                throw new KsiServiceProtocolException("Request timeout should be in milliseconds, but was (" + requestTimeout + ").");
            }
            _requestTimeOut = requestTimeout;
        }

        /// <summary>
        ///     Create TCP KSI service protocol with given url-s, request timeout and buffer size
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="signingPort">signing port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">buffer size</param>
        public TcpKsiServiceProtocol(string signingUrl, int signingPort, int requestTimeout, int bufferSize) : this(signingUrl, signingPort, requestTimeout)
        {
            if (bufferSize < 0)
            {
                throw new KsiServiceProtocolException("Buffer size should be in positive integer, but was (" + bufferSize + ").");
            }

            _bufferSize = bufferSize;
        }

        /// <summary>
        ///     Begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new KsiException("Invalid input data: null.");
            }

            IPHostEntry ipHostInfo;

            try
            {
                ipHostInfo = Dns.GetHostEntry(_signingUrl);
            }
            catch (Exception ex)
            {
                throw new KsiServiceProtocolException("Could not get host entry for TCP connection. Host: " + _signingUrl, ex);
            }

            IPAddress ipAddress = ipHostInfo.AddressList[0];
            IPEndPoint endPoint = new IPEndPoint(ipAddress, _signingPort);

            Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                SendTimeout = _requestTimeOut,
            };

            TcpKsiServiceProtocolAsyncResult asyncResult = new TcpKsiServiceProtocolAsyncResult(client, data, requestId, callback, asyncState, _bufferSize);

            Logger.Debug("Begin TCP socket connection (request id: {0}).", asyncResult.RequestId);
            client.BeginConnect(endPoint, ConnectCallback, asyncResult);

            ThreadPool.RegisterWaitForSingleObject(asyncResult.BeginWaitHandle, EndBeginSignCallback, asyncResult, _requestTimeOut, true);
            return asyncResult;
        }

        private void ConnectCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            try
            {
                // Complete the connection.
                asyncResult.Client.EndConnect(ar);
                Logger.Debug("Socket connected to {0}. (request id: {1}).", asyncResult.Client.RemoteEndPoint.ToString(), asyncResult.RequestId);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Completing connection failed.");
                return;
            }

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                Logger.Debug("Starting sending (request id: {0}).", asyncResult.RequestId);
                asyncResult.Client.BeginSend(asyncResult.PostData, 0, asyncResult.PostData.Length, 0, SendCallback, asyncResult);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Starting sending failed.");
            }
        }

        private void SendCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                // Complete sending the data to the remote device.
                int bytesSent = asyncResult.Client.EndSend(ar);
                Logger.Debug("{0} bytes sent to server. (request id: {1}).", bytesSent, asyncResult.RequestId);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Completing sending failed.");
                return;
            }

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                asyncResult.Client.ReceiveTimeout = _requestTimeOut - asyncResult.TimeElapsed;
                Logger.Debug("Starting receiving (request id: {0}).", asyncResult.RequestId);
                asyncResult.Client.BeginReceive(asyncResult.Buffer, 0, asyncResult.Buffer.Length, 0, ReceiveCallback, asyncResult);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Starting receiving failed.");
            }
        }

        private void ReceiveCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            try
            {
                Socket client = asyncResult.Client;

                if (asyncResult.IsCompleted)
                {
                    return;
                }

                // Read data from the remote device.
                int bytesRead = asyncResult.Client.EndReceive(ar);

                if (bytesRead == 0)
                {
                    SetError(asyncResult, null, "Received 0 bytes.");
                    return;
                }

                Logger.Debug("{0} bytes received (request id: {1}).", bytesRead, asyncResult.RequestId);

                asyncResult.ResultStream.Write(asyncResult.Buffer, 0, bytesRead);

                if (asyncResult.ExpectedResponseLength == 0)
                {
                    if (asyncResult.ResultStream.Length >= 4)
                    {
                        asyncResult.ExpectedResponseLength = Utils.Util.GetTlvLength(asyncResult.ResultStream.ToArray());
                    }
                }

                else if (asyncResult.ExpectedResponseLength < asyncResult.ResultStream.Length)
                {
                    SetError(asyncResult, null, "Received more bytes than expected.");
                    return;
                }

                if (asyncResult.ExpectedResponseLength == asyncResult.ResultStream.Length)
                {
                    Logger.Debug("Receiving done (request id: {0}).", asyncResult.RequestId);
                    // Signal that all bytes have been received.
                    asyncResult.BeginWaitHandle.Set();
                    return;
                }

                if (asyncResult.IsCompleted)
                {
                    return;
                }

                Logger.Debug("Rerun BeginReceive (request id: {0}).", asyncResult.RequestId);

                // Get the rest of the data.
                client.BeginReceive(asyncResult.Buffer, 0, asyncResult.Buffer.Length, 0, ReceiveCallback, asyncResult);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Receiving failed.");
            }
        }

        private void EndBeginSignCallback(object state, bool timedOut)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)state;

            if (timedOut)
            {
                asyncResult.Error = new KsiServiceProtocolException("Sign timed out.");
            }

            asyncResult.SetComplete(timedOut);
        }

        /// <summary>
        ///     End create signature.
        /// </summary>
        /// <param name="asyncResult">TCP KSI service protocol async result</param>
        /// <returns>aggregation response bytes</returns>
        public byte[] EndSign(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     End get result from web request.
        /// </summary>
        /// <param name="ar">TCP KSI service protocol async result</param>
        /// <returns>result bytes</returns>
        private byte[] EndGetResult(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = ar as TcpKsiServiceProtocolAsyncResult;
            if (asyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            if (!asyncResult.IsCompleted)
            {
                asyncResult.AsyncWaitHandle.WaitOne();
            }

            if (asyncResult.HasError)
            {
                throw asyncResult.Error;
            }

            Logger.Debug("Returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

            return asyncResult.ResultStream.ToArray();
        }

        private static void SetError(TcpKsiServiceProtocolAsyncResult asyncResult, Exception e, string errorMessage)
        {
            string message = errorMessage + string.Format(" (request id: {0}).", asyncResult.RequestId);
            Logger.Warn(message + " " + e);
            asyncResult.Error = new KsiServiceProtocolException(message, e);
            asyncResult.BeginWaitHandle.Set();
        }

        /// <summary>
        ///     TCP KSI service protocol async result.
        /// </summary>
        private class TcpKsiServiceProtocolAsyncResult : IAsyncResult, IDisposable
        {
            private readonly AsyncCallback _callback;
            private readonly object _lock;

            private readonly DateTime _startTime = DateTime.Now;
            private readonly ManualResetEvent _waitHandle;
            private bool _isCompleted;

            public TcpKsiServiceProtocolAsyncResult(Socket client, byte[] postData, ulong requestId, AsyncCallback callback,
                                                    object asyncState, int bufferSize)
            {
                if (client == null)
                {
                    throw new KsiException("Invalid tcp client: null.");
                }

                Client = client;
                PostData = postData;
                _callback = callback;
                AsyncState = asyncState;

                _isCompleted = false;

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);
                BeginWaitHandle = new ManualResetEvent(false);
                RequestId = requestId;
                ResultStream = new MemoryStream();
                Buffer = new byte[bufferSize];
            }

            public int ExpectedResponseLength { get; set; }

            public ulong RequestId { get; }

            public MemoryStream ResultStream { get; }

            public Socket Client { get; }

            public byte[] PostData { get; }

            public byte[] Buffer { get; }

            public int TimeElapsed => (int)(DateTime.Now - _startTime).TotalMilliseconds;

            public bool HasError => Error != null;

            public KsiServiceProtocolException Error { get; set; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => _waitHandle;

            public ManualResetEvent BeginWaitHandle { get; }

            public bool CompletedSynchronously => false;

            public bool IsCompleted
            {
                get
                {
                    lock (_lock)
                    {
                        return _isCompleted;
                    }
                }
            }

            public void Dispose()
            {
                _waitHandle.Close();
                BeginWaitHandle.Close();
                if (Client != null && Client.Connected)
                {
                    Client.Shutdown(SocketShutdown.Both);
                    Client.Close();
                    Logger.Debug("Connection closed (request id: {0}).", RequestId);
                }

                ResultStream?.Dispose();
            }

            public void SetComplete(bool errorOccured)
            {
                lock (_lock)
                {
                    if (!_isCompleted)
                    {
                        _isCompleted = true;

                        if (errorOccured == false)
                        {
                            _callback?.Invoke(this);
                        }
                    }
                }

                if (!_waitHandle.Set())
                {
                    throw new KsiException("WaitHandle completion failed");
                }
            }
        }
    }
}