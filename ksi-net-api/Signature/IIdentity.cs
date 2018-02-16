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

namespace Guardtime.KSI.Signature
{
    /// <summary>
    /// A structure that contains client identity and other information about the aggregation hash chain.
    /// </summary>
    public interface IIdentity
    {
        /// <summary>
        /// The type of the identity
        /// </summary>
        IdentityType IdentityType { get; }

        /// <summary>
        /// Client identifier
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// Machine identifier
        /// </summary>
        string MachineId { get; }

        /// <summary>
        /// A local sequence number of a request assigned by the machine that created the link
        /// </summary>
        ulong? SequenceNumber { get; }

        /// <summary>
        /// The time when the server received the request from the client (in milliseconds)
        /// </summary>
        ulong? RequestTime { get; }
    }
}