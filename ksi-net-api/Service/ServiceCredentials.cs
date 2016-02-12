/*
 * Copyright 2013-2016 Guardtime, Inc.
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