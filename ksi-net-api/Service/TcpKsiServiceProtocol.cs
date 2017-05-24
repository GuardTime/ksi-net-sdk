/*
 * Copyright 2013-2017 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// TCP KSI service protocol.
    /// When singing request is completed the tcp socket is left open and marked as available for future requests.
    /// New request takes an available socket if one exists and makes the request. If none is available a new socket is created.
    /// If the request using old socket fails (eg. socket is closed by server) it will be repeated once more with a new freshly connected socket.
    /// </summary>
    public class TcpKsiServiceProtocol : IKsiSigningServiceProtocol, IDisposable
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly uint _requestTimeOut = 10000;
        private readonly uint _bufferSize = 8192;
        private readonly IPAddress _ipAddress;
        private readonly ushort _port;
        private readonly Stack<Socket> _availableSockets = new Stack<Socket>();
        private readonly object _syncObj = new object();
        private bool _isDisposed;

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port)
        {
            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            _ipAddress = ipAddress;
            _port = port;
        }

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port, uint requestTimeout) : this(ipAddress, port)
        {
            _requestTimeOut = requestTimeout;
        }

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port, uint requestTimeout, uint bufferSize) : this(ipAddress, port, requestTimeout)
        {
            if (bufferSize == 0)
            {
                throw new KsiServiceProtocolException("Buffer size should be in positive integer, but was (" + bufferSize + ").");
            }

            _bufferSize = bufferSize;
        }

        /// <summary>
        /// Dispose TCP KSI service protocol. Close opened connections.
        /// </summary>
        public void Dispose()
        {
            Logger.Debug("Disposing.");

            lock (_syncObj)
            {
                _isDisposed = true;

                while (_availableSockets.Count > 0)
                {
                    Socket socket = _availableSockets.Pop();
                    CloseSocket(socket);
                }
            }
        }

        private static void CloseSocket(Socket socket)
        {
            Logger.Debug("Closing socket. Handle: " + socket.Handle);
            socket.Shutdown(SocketShutdown.Both);
            socket.Disconnect(false);
            socket.Close();
        }

        /// <summary>
        ///     Begin signing request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (_isDisposed)
            {
                throw new KsiServiceProtocolException("TCP KSI service protocol is disposed.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            Socket socket = GetSocket(requestId);
            TcpKsiServiceProtocolAsyncResult asyncResult = new TcpKsiServiceProtocolAsyncResult(socket, data, requestId, callback, asyncState, _bufferSize);
            BeginSocketConnect(asyncResult);
            ThreadPool.RegisterWaitForSingleObject(asyncResult.BeginWaitHandle, EndBeginSignCallback, asyncResult, _requestTimeOut, true);
            return asyncResult;
        }

        private void BeginSocketConnect(TcpKsiServiceProtocolAsyncResult asyncResult)
        {
            if (asyncResult.Socket.Connected)
            {
                Logger.Debug("Re-using already connected TCP socket. (Socket handle: {0}; request id: {1}).", asyncResult.Socket.Handle, asyncResult.RequestId);
                BeginSend(asyncResult);
            }
            else
            {
                Logger.Debug("Begin TCP socket connection. (Socket handle: {0}; request id: {1}).", asyncResult.Socket.Handle, asyncResult.RequestId);
                asyncResult.Socket.BeginConnect(new IPEndPoint(_ipAddress, _port), ConnectCallback, asyncResult);
            }
        }

        /// <summary>
        /// Get a connected socked from queue or create new.
        /// </summary>
        /// <returns></returns>
        private Socket GetSocket(ulong requestId)
        {
            Socket s;

            lock (_syncObj)
            {
                if (_availableSockets.Count > 0)
                {
                    s = _availableSockets.Pop();
                    Logger.Debug("An available socket found to be re-used. (Socket handle: {0}; request id: {1}).", s.Handle, requestId);
                    return s;
                }
            }

            return CreateSocket(requestId);
        }

        private static Socket CreateSocket(ulong requestId)
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Logger.Debug("New TCP socket created. (Socket handle: {0}; request id: {1}).", s.Handle, requestId);
            return s;
        }

        private void ConnectCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            try
            {
                // Complete the connection.
                asyncResult.Socket.EndConnect(ar);
                Logger.Debug("Socket connected to {0} (request id: {1}).", asyncResult.Socket.RemoteEndPoint.ToString(), asyncResult.RequestId);
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

            BeginSend(asyncResult);
        }

        private void BeginSend(TcpKsiServiceProtocolAsyncResult asyncResult)
        {
            try
            {
                Logger.Debug("Starting sending (request id: {0}).", asyncResult.RequestId);
                asyncResult.Socket.BeginSend(asyncResult.PostData, 0, asyncResult.PostData.Length, 0, SendCallback, asyncResult);
            }
            catch (Exception e)
            {
                RetryOrSetError(asyncResult, e, "Failed to start sending.");
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
                int bytesSent = asyncResult.Socket.EndSend(ar);
                Logger.Debug("{0} bytes sent to server (request id: {1}).", bytesSent, asyncResult.RequestId);
            }
            catch (Exception e)
            {
                RetryOrSetError(asyncResult, e, "Failed to complete sending.");
                return;
            }

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                Logger.Debug("Starting receiving (request id: {0}).", asyncResult.RequestId);
                asyncResult.Socket.BeginReceive(asyncResult.Buffer, 0, asyncResult.Buffer.Length, 0, ReceiveCallback, asyncResult);
            }
            catch (Exception e)
            {
                RetryOrSetError(asyncResult, e, "Failed to start receiving.");
            }
        }

        private void ReceiveCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            try
            {
                if (asyncResult.IsCompleted)
                {
                    return;
                }

                // Read data from the remote device.
                int bytesRead = asyncResult.Socket.EndReceive(ar);

                if (bytesRead == 0)
                {
                    RetryOrSetError(asyncResult, null, "Received 0 bytes.");
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

                // Get the rest of the data.
                Logger.Debug("Rerun BeginReceive (request id: {0}).", asyncResult.RequestId);
                asyncResult.Socket.BeginReceive(asyncResult.Buffer, 0, asyncResult.Buffer.Length, 0, ReceiveCallback, asyncResult);
            }
            catch (Exception e)
            {
                RetryOrSetError(asyncResult, e, "Receiving failed.");
            }
        }

        private void EndBeginSignCallback(object state, bool timedOut)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)state;

            if (timedOut)
            {
                asyncResult.Error = new KsiServiceProtocolException(string.Format("Sign timed out (request id: {0}).", asyncResult.RequestId));
            }

            asyncResult.SetComplete(timedOut);
        }

        /// <summary>
        ///     End signing request.
        /// </summary>
        /// <param name="ar">TCP KSI service protocol async result</param>
        /// <returns>aggregation response bytes</returns>
        public byte[] EndSign(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = ar as TcpKsiServiceProtocolAsyncResult;
            if (asyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            try
            {
                if (_isDisposed)
                {
                    throw new KsiServiceProtocolException("TCP KSI service protocol is disposed.");
                }

                if (asyncResult.IsDisposed)
                {
                    throw new KsiServiceProtocolException("Provided async result is already disposed. Possibly using the same async result twice when calling EndSign().");
                }

                if (!asyncResult.IsCompleted)
                {
                    asyncResult.AsyncWaitHandle.WaitOne();
                }

                if (asyncResult.HasError)
                {
                    Logger.Warn("{0} (request id: {1}){2}{3}", asyncResult.Error.Message, asyncResult.RequestId, Environment.NewLine, asyncResult.Error);
                    throw asyncResult.Error;
                }

                Logger.Debug("Returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

                return asyncResult.ResultStream.ToArray();
            }
            finally
            {
                bool isAdded = false;
                lock (_syncObj)
                {
                    if (!_isDisposed)
                    {
                        if (!_availableSockets.Contains(asyncResult.Socket))
                        {
                            _availableSockets.Push(asyncResult.Socket);
                            isAdded = true;
                        }
                    }
                }

                if (!isAdded)
                {
                    CloseSocket(asyncResult.Socket);
                }

                asyncResult.Dispose();
            }
        }

        private void RetryOrSetError(TcpKsiServiceProtocolAsyncResult asyncResult, Exception ex, string message)
        {
            if ((ex == null || ex is SocketException) && asyncResult.IsFirstTry)
            {
                Logger.Debug(message + " Re-trying with a new socket (request id: {0}).", asyncResult.RequestId);
                asyncResult.IsFirstTry = false;
                CloseSocket(asyncResult.Socket);

                lock (_syncObj)
                {
                    // close all available sockets because they are even older and moste likely not connected
                    while (_availableSockets.Count > 0)
                    {
                        CloseSocket(_availableSockets.Pop());
                    }
                }

                asyncResult.Socket = CreateSocket(asyncResult.RequestId);
                BeginSocketConnect(asyncResult);
            }
            else
            {
                SetError(asyncResult, ex, message);
            }
        }

        private static void SetError(TcpKsiServiceProtocolAsyncResult asyncResult, Exception e, string errorMessage)
        {
            asyncResult.Error = new KsiServiceProtocolException(errorMessage, e);
            asyncResult.BeginWaitHandle.Set();
            Logger.Debug("Closing socket due to error. Handle: " + asyncResult.Socket.Handle);
            asyncResult.Socket.Close();
        }

        /// <summary>
        ///     TCP KSI service protocol async result.
        /// </summary>
        private class TcpKsiServiceProtocolAsyncResult : IAsyncResult, IDisposable
        {
            private readonly AsyncCallback _callback;
            private readonly object _lock;
            private readonly ManualResetEvent _waitHandle;
            private bool _isCompleted;
            private bool _isDisposed;

            public TcpKsiServiceProtocolAsyncResult(Socket socket, byte[] postData, ulong requestId, AsyncCallback callback,
                                                    object asyncState, uint bufferSize)
            {
                if (socket == null)
                {
                    throw new ArgumentNullException(nameof(socket));
                }

                Socket = socket;
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
                IsFirstTry = true;
            }

            public int ExpectedResponseLength { get; set; }

            public ulong RequestId { get; }

            public MemoryStream ResultStream { get; }

            public Socket Socket { get; set; }

            public byte[] PostData { get; }

            public byte[] Buffer { get; }

            public bool HasError => Error != null;

            public KsiServiceProtocolException Error { get; set; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => _waitHandle;

            public ManualResetEvent BeginWaitHandle { get; }

            public bool CompletedSynchronously => false;

            public bool IsFirstTry { get; set; }

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

            public bool IsDisposed => _isDisposed;

            public void Dispose()
            {
                _waitHandle.Close();
                BeginWaitHandle.Close();
                ResultStream?.Dispose();
                _isDisposed = true;
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
                    throw new KsiServiceProtocolException("WaitHandle completion failed");
                }
            }
        }
    }
}