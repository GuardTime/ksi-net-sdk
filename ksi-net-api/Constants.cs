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

#pragma warning disable 1591

namespace Guardtime.KSI
{
    public static class Constants
    {
        /// <summary>
        ///     Bits in byte
        /// </summary>
        public const byte BitsInByte = 8;

        public static class Tlv
        {
            /// <summary>
            ///     TLV element 16 bit flag
            /// </summary>
            public const byte Tlv16Flag = 0x80;

            /// <summary>
            ///     TLV element non critical flag
            /// </summary>
            public const byte NonCriticalFlag = 0x40;

            /// <summary>
            ///     TLV element forward flag
            /// </summary>
            public const byte ForwardFlag = 0x20;

            /// <summary>
            ///     TLV element type mask.
            /// </summary>
            public const byte TypeMask = 0x1f;

            /// <summary>
            ///     TLV element max type.
            /// </summary>
            public const ushort MaxType = 0x1fff;
        }

        public static class CertificateRecord
        {
            public const uint TagType = 0x702;
            public const uint CertificateIdTagType = 0x1;
            public const uint X509CertificateTagType = 0x2;
        }

        public static class SignatureData
        {
            /// <summary>
            ///     Signature data tag type
            /// </summary>
            public const uint TagType = 0xb;

            public const uint SignatureTypeTagType = 0x1;
            public const uint SignatureValueTagType = 0x2;
            public const uint CertificateIdTagType = 0x3;
            public const uint CertificateRepositoryUriTagType = 0x4;
        }

        public static class PublicationData
        {
            /// <summary>
            ///     Publication data tag type.
            /// </summary>
            public const uint TagType = 0x10;

            public const uint PublicationTimeTagType = 0x2;
            public const uint PublicationHashTagType = 0x4;
        }

        public static class PublicationRecord
        {
            /// <summary>
            ///     Publication record TLV type in Signature.
            /// </summary>
            public const uint TagTypeInSignature = 0x803;

            /// <summary>
            ///     Publication record TLV type in Publications file.
            /// </summary>
            public const uint TagTypeInPublicationsFile = 0x703;

            public const uint PublicationReferencesTagType = 0x9;
            public const uint PublicationRepositoryUriTagType = 0xa;
        }

        public static class PublicationsFile
        {
            public const uint CmsSignatureTagType = 0x704;
        }

        public static class PublicationsFileHeader
        {
            /// <summary>
            ///     Publications file header TLV type.
            /// </summary>
            public const uint TagType = 0x701;

            public const uint VersionTagType = 0x1;
            public const uint CreationTimeTagType = 0x2;
            public const uint RepositoryUriTagType = 0x3;
        }

        public static class KsiPdu
        {
            /// <summary>
            ///     Mac TLV type.
            /// </summary>
            public const uint MacTagType = 0x1f;
        }

        public static class KsiPduPayload
        {
            /// <summary>
            ///     Status TLV element type.
            /// </summary>
            public const uint StatusTagType = 0x4;

            /// <summary>
            ///     Error message TLV element type.
            /// </summary>
            public const uint ErrorMessageTagType = 0x5;
        }

        [Obsolete]
        public static class LegacyAggregationPdu
        {
            /// <summary>
            ///     Aggregation PDU TLV type.
            /// </summary>
            public const uint TagType = 0x200;
        }

        public static class AggregationPdu
        {
            /// <summary>
            ///     Aggregation PDU TLV type.
            /// </summary>
            public const uint TagType = 0x2FF;
        }

        public static class AggregationRequestPayload

        {
            /// <summary>
            ///     Aggregation request TLV type.
            /// </summary>
            public const uint TagType = 0x201;

            public const uint RequestIdTagType = 0x1;
            public const uint RequestHashTagType = 0x2;
            public const uint RequestLevelTagType = 0x3;

            [Obsolete]
            public const uint ConfigTagType = 0x10;
        }

        public static class AggregationResponsePayload
        {
            /// <summary>
            ///     Aggregation response payload TLV type.
            /// </summary>
            public const uint TagType = 0x202;

            public const uint RequestIdTagType = 0x1;

            [Obsolete]
            public const uint ConfigTagType = 0x10;

            [Obsolete]
            public const uint RequestAcknowledgmentTagType = 0x11;
        }

        public static class AggregationErrorPayload
        {
            /// <summary>
            ///     Aggregation error payload TLV type.
            /// </summary>
            public const uint TagType = 0x203;
        }

        public static class AggregationConfigRequestPayload
        {
            /// <summary>
            ///     Aggregation config request TLV type.
            /// </summary>
            public const uint TagType = 0x204;
        }

        public static class AggregationConfigResponsePayload
        {
            /// <summary>
            ///     Aggregation config response payload TLV type.
            /// </summary>
            public const uint TagType = 0x205;

            public const uint AggregationPeriodTagType = 0x1;

            public const uint AggregationAlgorithmTagType = 0x2;

            public const uint MaxLevelTagType = 0x3;

            public const uint MaxRequestsTagType = 0x4;

            public const uint ParentUriTagType = 0x10;
        }

        [Obsolete]
        public static class LegacyExtendPdu
        {
            /// <summary>
            ///     Extension PDU TLV type.
            /// </summary>
            public const uint TagType = 0x300;
        }

        public static class ExtendPdu
        {
            /// <summary>
            ///     Extend PDU TLV type.
            /// </summary>
            public const uint TagType = 0x3FF;
        }

        public static class ExtendRequestPayload
        {
            /// <summary>
            ///     Extend request payload TLV type.
            /// </summary>
            public const uint TagType = 0x301;

            public const uint RequestIdTagType = 0x1;
            public const uint AggregationTimeTagType = 0x2;
            public const uint PublicationTimeTagType = 0x3;
        }

        public static class ExtendResponsePayload
        {
            /// <summary>
            ///     Extend response payload TLV type.
            /// </summary>
            public const uint TagType = 0x302;

            public const uint RequestIdTagType = 0x1;

            [Obsolete]
            public const uint LastTimeTagType = 0x10;

            public const uint CalendarLastTimeTagType = 0x12;
        }

        public static class ExtendErrorPayload
        {
            /// <summary>
            ///     Extend error payload TLV type.
            /// </summary>
            public const uint TagType = 0x303;
        }

        public static class KsiPduHeader
        {
            /// <summary>
            ///     KSI PDU header TLV type.
            /// </summary>
            public const uint TagType = 0x1;

            public const uint LoginIdTagType = 0x1;
            public const uint InstanceIdTagType = 0x2;
            public const uint MessageIdTagType = 0x3;
        }

        public static class AggregationAuthenticationRecord
        {
            /// <summary>
            ///     Aggregation authentication record tag type
            /// </summary>
            public const uint TagType = 0x804;

            public const uint AggregationTimeTagType = 0x2;
            public const uint ChainIndexTagType = 0x3;
            public const uint InputHashTagType = 0x5;
        }

        public static class AggregationHashChain
        {
            /// <summary>
            ///     Aggregation hash chain TLV type.
            /// </summary>
            public const uint TagType = 0x801;

            public const uint AggregationTimeTagType = 0x2;
            public const uint ChainIndexTagType = 0x3;
            public const uint InputDataTagType = 0x4;
            public const uint InputHashTagType = 0x5;
            public const uint AggregationAlgorithmIdTagType = 0x6;

            public static class Link
            {
                public const uint LevelCorrectionTagType = 0x1;
                public const uint SiblingHashTagType = 0x2;
                public const uint LegacyId = 0x3;
            }

            public static class Metadata
            {
                /// <summary>
                ///     Metadata TLV type.
                /// </summary>
                // ReSharper disable once MemberHidesStaticFromOuterClass
                public const uint TagType = 0x4;

                public const uint PaddingTagType = 0x1E;
                public const uint ClientIdTagType = 0x1;
                public const uint MachineIdTagType = 0x2;
                public const uint SequenceNumberTagType = 0x3;
                public const uint RequestTimeTagType = 0x4;
            }
        }

        public static class CalendarAuthenticationRecord
        {
            /// <summary>
            ///     Calendar authentication record TLV type
            /// </summary>
            public const uint TagType = 0x805;
        }

        public static class CalendarHashChain
        {
            /// <summary>
            ///     Calendar hash chain tag type
            /// </summary>
            public const uint TagType = 0x802;

            public const uint PublicationTimeTagType = 0x1;
            public const uint AggregationTimeTagType = 0x2;
            public const uint InputHashTagType = 0x5;
        }

        public static class KsiSignature
        {
            /// <summary>
            ///     KSI signature tag type
            /// </summary>
            public const uint TagType = 0x800;
        }

        public static class Rfc3161Record
        {
            /// <summary>
            ///     RFC3161 record tag type
            /// </summary>
            public const uint TagType = 0x806;

            public const uint AggregationTimeTagType = 0x2;
            public const uint ChainIndexTagType = 0x3;
            public const uint InputHashTagType = 0x5;
            public const uint TstInfoPrefixTagType = 0x10;
            public const uint TstInfoSuffixTagType = 0x11;
            public const uint TstInfoAlgorithmTagType = 0x12;
            public const uint SignedAttributesPrefixTagType = 0x13;
            public const uint SignedAttributesSuffixTagType = 0x14;
            public const uint SignedAttributesAlgorithmTagType = 0x15;
        }
    }
}