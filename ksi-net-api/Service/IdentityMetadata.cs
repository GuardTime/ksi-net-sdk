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

using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Metadata to be added to the signature.
    /// </summary>
    public class IdentityMetadata
    {
        AggregationHashChain.Metadata _aggregationHashChainMetadata;

        /// <summary>
        /// Create new identity metadata instance
        /// </summary>
        /// <param name="clientId">Client identifier</param>
        public IdentityMetadata(string clientId) : this(clientId, null)
        {
        }

        /// <summary>
        /// Create new identity metadata instance
        /// </summary>
        /// <param name="clientId">Client identifier</param>
        /// <param name="machineId">Machine identifier</param>
        /// <param name="sequenceNumber">Sequence number</param>
        /// <param name="requestTime">Request time</param>
        public IdentityMetadata(string clientId, string machineId, ulong? sequenceNumber = null, ulong? requestTime = null)
        {
            ClientId = clientId;
            MachineId = machineId;
            SequenceNumber = sequenceNumber;
            RequestTime = requestTime;
        }

        /// <summary>
        /// Client identifier
        /// </summary>
        public string ClientId { get; }

        /// <summary>
        /// Machine identifier
        /// </summary>
        public string MachineId { get; }

        /// <summary>
        /// Sequence number
        /// </summary>
        public ulong? SequenceNumber { get; }

        /// <summary>
        /// Request time
        /// </summary>
        public ulong? RequestTime { get; }

        /// <summary>
        /// Get AggregationHashChain.Metadata object created based on the current object property values
        /// </summary>
        public AggregationHashChain.Metadata AggregationHashChainMetadata
            => _aggregationHashChainMetadata ?? (_aggregationHashChainMetadata = new AggregationHashChain.Metadata(ClientId, MachineId, SequenceNumber, RequestTime));
    }
}