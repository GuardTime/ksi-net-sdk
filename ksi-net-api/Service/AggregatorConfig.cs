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

using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Aggregator configuration data.
    /// </summary>
    public sealed class AggregatorConfig
    {
        /// <summary>
        /// Create new aggregator configuration data instance
        /// </summary>
        /// <param name="payload">Aggregator config response payload</param>
        public AggregatorConfig(AggregatorConfigResponsePayload payload)
        {
            MaxLevel = payload.MaxLevel;
            AggregationAlgorithm = payload.AggregationAlgorithm;
            AggregationPeriod = payload.AggregationPeriod;
            MaxRequests = payload.MaxRequests;
            ParentsUris = payload.ParentsUris;
        }

        /// <summary>
        /// Maximum level value that the nodes in the client's aggregation tree are allowed to have
        /// </summary>
        public ulong? MaxLevel { get; }

        /// <summary>
        /// Identifier of the hash function that the client is recommended to use in its aggregation trees
        /// </summary>
        public ulong? AggregationAlgorithm { get; }

        /// <summary>
        /// Recommended duration of client's aggregation round, in milliseconds
        /// </summary>
        public ulong? AggregationPeriod { get; }

        /// <summary>
        /// Maximum number of requests the client is allowed to send within one parent server's aggregation round
        /// </summary>
        public ulong? MaxRequests { get; }

        /// <summary>
        /// Parent server URI (may be several parent servers)
        /// </summary>
        public IList<string> ParentsUris { get; }
    }
}