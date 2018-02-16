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
using Guardtime.KSI.Service.Tcp;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// TCP KSI service protocol for signing.
    /// </summary>
    [Obsolete("Use TcpKsiSigningServiceProtocol instead.")]
    public class TcpKsiServiceProtocol : TcpKsiSigningServiceProtocol
    {
        /// <summary>
        ///     Create TCP KSI service protocol for signing.
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port, uint? requestTimeout = null, uint? bufferSize = null)
            : base(ipAddress, port, requestTimeout, bufferSize)
        {
        }
    }
}