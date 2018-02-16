/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using System.Net;

namespace Guardtime.KSI.Service.Tcp
{
    /// <summary>
    /// TCP KSI extending service protocol.
    /// Responsible for making TCP requests to extender.
    /// All requests and responses go through one socket that is kept opened for future requests.
    /// If a request fails (eg. socket is closed by server) it will be repeated once more with a new freshly connected socket.
    /// </summary>
    public class TcpKsiExtendingServiceProtocol : TcpKsiServiceProtocolBase, IKsiExtendingServiceProtocol
    {
        /// <summary>
        ///     Create TCP KSI extending service protocol
        /// </summary>
        /// <param name="ipAddress">Service IP address</param>
        /// <param name="port">Service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiExtendingServiceProtocol(IPAddress ipAddress, ushort port, uint? requestTimeout = null, uint? bufferSize = null)
            : base(ipAddress, port, requestTimeout, bufferSize)
        {
        }

        /// <summary>
        ///    Begin extending request.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending request is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginRequest(KsiServiceRequestType.Extend, data, requestId, callback, asyncState);
        }

        /// <summary>
        ///       Begin extender configuration request.
        /// </summary>
        /// <param name="data">extender configuration request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extender configuration request is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginGetExtenderConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginRequest(KsiServiceRequestType.ExtenderConfig, data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     End extending request.
        /// </summary>
        /// <param name="ar">TCP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndExtend(IAsyncResult ar)
        {
            return EndRequest(ar);
        }

        /// <summary>
        ///     End extender configuration request.
        /// </summary>
        /// <param name="ar">async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetExtenderConfig(IAsyncResult ar)
        {
            return EndRequest(ar);
        }

        /// <summary>
        /// Extender ip and port
        /// </summary>
        public string ExtenderAddress => ServiceAddress;
    }
}