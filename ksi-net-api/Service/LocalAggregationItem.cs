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

using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// This class holds info for doing local aggregation. 
    /// It contains document hash to be signed and metadata to be added to aggregation hash chain.
    /// After signing it will contain signature for the given document hash.
    /// </summary>
    public class LocalAggregationItem
    {
        /// <summary>
        /// Create aggregation item instance
        /// </summary>
        /// <param name="documentHash">Document hash</param>
        /// <param name="metaData">Metadata to be added to aggregation hash chain</param>
        /// <exception cref="ArgumentNullException"></exception>
        public LocalAggregationItem(DataHash documentHash, AggregationHashChain.MetaData metaData)
        {
            if (documentHash == null)
            {
                throw new ArgumentNullException(nameof(documentHash));
            }

            if (metaData == null)
            {
                throw new ArgumentNullException(nameof(metaData));
            }

            DocumentHash = documentHash;
            MetaData = metaData;
        }

        /// <summary>
        /// Document hash value
        /// </summary>
        public DataHash DocumentHash { get; }

        /// <summary>
        /// Metadata to be added to aggregation hash chain
        /// </summary>
        public AggregationHashChain.MetaData MetaData { get; }

        /// <summary>
        /// Created KSI signature for given document hash
        /// </summary>
        public IKsiSignature Signature { get; set; }
    }
}