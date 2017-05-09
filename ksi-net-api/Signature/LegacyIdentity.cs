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

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// Structure for holding legacy identity.
    /// </summary>
    public class LegacyIdentity : IIdentity
    {
        /// <summary>
        /// Create a new legacy identity holder
        /// </summary>
        /// <param name="clientId"></param>
        public LegacyIdentity(string clientId)
        {
            ClientId = clientId;
        }

        /// <summary>
        /// The type of the identity
        /// </summary>
        public IdentityType IdentityType => IdentityType.Legacy;

        /// <summary>
        /// Client identifier
        /// </summary>
        public string ClientId { get; }

        /// <summary>
        /// Machine identifier
        /// </summary>
        public string MachineId => null;

        /// <summary>
        /// A local sequence number of a request assigned by the machine that created the link
        /// </summary>
        public ulong? SequenceNumber => null;

        /// <summary>
        /// The time when the server received the request from the client (in milliseconds)
        /// </summary>
        public ulong? RequestTime => null;
    }
}