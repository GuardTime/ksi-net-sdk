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

using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature
{
    public sealed partial class AggregationHashChain
    {
        /// <summary>
        /// Aggregation hash chain link metadata TLV element.
        /// </summary>
        public class Metadata : CompositeTag, IIdentity
        {
            private StringTag _clientId;
            private StringTag _machineId;
            private IntegerTag _sequenceNumber;
            private IntegerTag _requestTime;

            /// <summary>
            /// Expected tag type
            /// </summary>
            protected override uint ExpectedTagType => Constants.AggregationHashChain.Metadata.TagType;

            /// <summary>
            /// Create new aggregation hash chain link metadata TLV element
            /// </summary>
            /// <param name="clientId">Client identifier</param>
            public Metadata(string clientId) : this(clientId, null)
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link metadata TLV element
            /// </summary>
            /// <param name="clientId">Client identifier</param>
            /// <param name="machineId">Machine identifier</param>
            /// <param name="sequenceNumber">Sequence number</param>
            /// <param name="requestTime">Request time</param>
            public Metadata(string clientId, string machineId, ulong? sequenceNumber = null, ulong? requestTime = null)
                : base(Constants.AggregationHashChain.Metadata.TagType, false, false, BuildChildTags(clientId, machineId, sequenceNumber, requestTime))
            {
            }

            /// <summary>
            /// Create new aggregation hash chain link metadata TLV element from TLV element
            /// </summary>
            /// <param name="tag">TLV element</param>
            public Metadata(ITlvTag tag) : base(tag)
            {
            }

            /// <summary>
            /// Parse child element
            /// </summary>
            protected override ITlvTag ParseChild(ITlvTag childTag)
            {
                switch (childTag.Type)
                {
                    case Constants.AggregationHashChain.Metadata.PaddingTagType:
                        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
                        if (childTag is PaddingTag)
                        {
                            Padding = (PaddingTag)childTag;
                        }
                        else if (childTag is RawTag)
                        {
                            Padding = new PaddingTag((RawTag)childTag, Count);
                        }
                        else
                        {
                            throw new TlvException("Invalid tag type for creating padding tag. Tag: " + childTag);
                        }

                        return Padding;

                    case Constants.AggregationHashChain.Metadata.ClientIdTagType:
                        return _clientId = GetStringTag(childTag);
                    case Constants.AggregationHashChain.Metadata.MachineIdTagType:
                        return _machineId = GetStringTag(childTag);
                    case Constants.AggregationHashChain.Metadata.SequenceNumberTagType:
                        return _sequenceNumber = GetIntegerTag(childTag);
                    case Constants.AggregationHashChain.Metadata.RequestTimeTagType:
                        return _requestTime = GetIntegerTag(childTag);
                    default:
                        return base.ParseChild(childTag);
                }
            }

            /// <summary>
            /// Validate the tag
            /// </summary>
            protected override void Validate(TagCounter tagCounter)
            {
                base.Validate(tagCounter);

                if (tagCounter[Constants.AggregationHashChain.Metadata.ClientIdTagType] != 1)
                {
                    throw new TlvException("Exactly one client id must exist in aggregation hash chain link metadata.");
                }

                if (tagCounter[Constants.AggregationHashChain.Metadata.MachineIdTagType] > 1)
                {
                    throw new TlvException("Only one machine id is allowed in aggregation hash chain link metadata.");
                }

                if (tagCounter[Constants.AggregationHashChain.Metadata.SequenceNumberTagType] > 1)
                {
                    throw new TlvException("Only one sequence number is allowed in aggregation hash chain link metadata.");
                }

                if (tagCounter[Constants.AggregationHashChain.Metadata.RequestTimeTagType] > 1)
                {
                    throw new TlvException("Only one request time is allowed in aggregation hash chain link metadata.");
                }
            }

            /// <summary>
            /// Create child TLV element list
            /// </summary>
            /// <param name="clientId">Client identifier</param>
            /// <param name="machineId">Machine identifier</param>
            /// <param name="requestTime">Request time</param>
            /// <param name="sequenceNumber">Sequence number</param>
            /// <returns></returns>
            private static ITlvTag[] BuildChildTags(string clientId, string machineId, ulong? sequenceNumber = null, ulong? requestTime = null)
            {
                List<ITlvTag> list = new List<ITlvTag>();

                if (!string.IsNullOrEmpty(clientId))
                {
                    list.Add(new StringTag(Constants.AggregationHashChain.Metadata.ClientIdTagType, false, false, clientId));
                }

                if (!string.IsNullOrEmpty(machineId))
                {
                    list.Add(new StringTag(Constants.AggregationHashChain.Metadata.MachineIdTagType, false, false, machineId));
                }

                if (sequenceNumber.HasValue)
                {
                    list.Add(new IntegerTag(Constants.AggregationHashChain.Metadata.SequenceNumberTagType, false, false, sequenceNumber.Value));
                }

                if (requestTime.HasValue)
                {
                    list.Add(new IntegerTag(Constants.AggregationHashChain.Metadata.RequestTimeTagType, false, false, requestTime.Value));
                }

                ushort tagsLength = 0;

                foreach (ITlvTag tag in list)
                {
                    tagsLength += Util.GetTlvLength(tag);
                }

                list.Insert(0, new PaddingTag(tagsLength % 2 == 0));

                return list.ToArray();
            }

            /// <summary>
            /// The type of the identity
            /// </summary>
            public IdentityType IdentityType => Padding != null ? IdentityType.PaddedMetadata : IdentityType.Metadata;

            /// <summary>
            /// Padding element
            /// </summary>
            public PaddingTag Padding { get; private set; }

            /// <summary>
            /// Client identifier
            /// </summary>
            public string ClientId => _clientId.Value;

            /// <summary>
            /// Machine identifier
            /// </summary>
            public string MachineId => _machineId.Value;

            /// <summary>
            /// A local sequence number of a request assigned by the machine that created the link
            /// </summary>
            public ulong? SequenceNumber => _sequenceNumber?.Value;

            /// <summary>
            /// The time when the server received the request from the client (in milliseconds)
            /// </summary>
            public ulong? RequestTime => _requestTime?.Value;

            /// <summary>
            /// Padding tag for metadata element
            /// </summary>
            public class PaddingTag : RawTag
            {
                private static readonly byte[] OddValue = new byte[] { 0x01 };
                private static readonly byte[] EvenValue = new byte[] { 0x01, 0x01 };

                /// <summary>
                /// Create new metadata padding element
                /// </summary>
                /// <param name="evenValue"></param>
                public PaddingTag(bool evenValue) : base(Constants.AggregationHashChain.Metadata.PaddingTagType, true, true, evenValue ? EvenValue : OddValue, false)
                {
                }

                /// <summary>
                /// Create new metadata padding element from TLV element
                /// </summary>
                /// <param name="tag">TLV element</param>
                /// <param name="index">Padding element index inside the metadata element</param>
                public PaddingTag(RawTag tag, int index) : base(tag.Type, tag.NonCritical, tag.Forward, tag.Value, tag.IsReadAsTlv16)
                {
                    Index = index;
                }

                /// <summary>
                /// Padding element index inside the metadata element
                /// </summary>       
                public int Index { get; }

                /// <summary>
                /// Is TLV16 encoding forced when writing the TLV object
                /// </summary>
                public override bool ForceTlv16Encoding => IsReadAsTlv16 != false;

                /// <summary>
                /// Returns true if value is 01 or 0101
                /// </summary>
                /// <returns></returns>
                public bool HasKnownValue()
                {
                    byte[] value = EncodeValue();
                    return Util.IsArrayEqual(value, EvenValue) || Util.IsArrayEqual(value, OddValue);
                }
            }
        }
    }
}