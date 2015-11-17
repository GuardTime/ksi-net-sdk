namespace Guardtime.KSI
{
    internal static class Constants
    {
        /// <summary>
        ///     Bits in byte
        /// </summary>
        internal const byte BitsInByte = 8;

        internal static class Tlv
        {
            /// <summary>
            ///     TLV element 16 bit flag
            /// </summary>
            internal const byte Tlv16Flag = 0x80;

            /// <summary>
            ///     TLV element non critical flag
            /// </summary>
            internal const byte NonCriticalFlag = 0x40;

            /// <summary>
            ///     TLV element forward flag
            /// </summary>
            internal const byte ForwardFlag = 0x20;

            /// <summary>
            ///     TLV element type mask.
            /// </summary>
            internal const byte TypeMask = 0x1f;

            /// <summary>
            ///     TLV element max type.
            /// </summary>
            internal const ushort MaxType = 0x1fff;
        }

        internal static class CertificateRecord
        {
            internal const uint TagType = 0x702;
            internal const uint CertificateIdTagType = 0x1;
            internal const uint X509CertificateTagType = 0x2;
        }

        internal static class SignatureData
        {
            /// <summary>
            ///     Signature data tag type
            /// </summary>
            internal const uint TagType = 0xb;

            internal const uint SignatureTypeTagType = 0x1;
            internal const uint SignatureValueTagType = 0x2;
            internal const uint CertificateIdTagType = 0x3;
            internal const uint CertificateRepositoryUriTagType = 0x4;
        }

        internal static class PublicationData
        {
            /// <summary>
            ///     Publication data tag type.
            /// </summary>
            internal const uint TagType = 0x10;

            internal const uint PublicationTimeTagType = 0x2;
            internal const uint PublicationHashTagType = 0x4;
        }

        internal static class PublicationRecord
        {
            /// <summary>
            ///     Signature publication record TLV type.
            /// </summary>
            internal const uint TagTypeSignature = 0x803;

            /// <summary>
            ///     Publication publication record TLV type.
            /// </summary>
            internal const uint TagTypePublication = 0x703;

            internal const uint PublicationReferencesTagType = 0x9;
            internal const uint PublicationRepositoryUriTagType = 0xa;
        }

        internal static class PublicationsFile
        {
            internal const uint CmsSignatureTagType = 0x704;
        }

        internal static class PublicationsFileHeader
        {
            /// <summary>
            ///     Publications file header TLV type.
            /// </summary>
            internal const uint TagType = 0x701;

            internal const uint VersionTagType = 0x1;
            internal const uint CreationTimeTagType = 0x2;
            internal const uint RepUriTagType = 0x3;
        }

        internal static class KsiPdu
        {
            /// <summary>
            ///     Mac TLV type.
            /// </summary>
            internal const uint MacTagType = 0x1f;
        }

        internal static class KsiPduPayload
        {
            /// <summary>
            ///     Status TLV element type.
            /// </summary>
            internal const uint StatusTagType = 0x4;

            /// <summary>
            ///     Error message TLV element type.
            /// </summary>
            internal const uint ErrorMessageTagType = 0x5;
        }

        internal static class AggregationErrorPayload
        {
            /// <summary>
            ///     Aggregation error payload TLV type.
            /// </summary>
            internal const uint TagType = 0x203;
        }

        internal static class AggregationPdu
        {
            /// <summary>
            ///     Aggregation PDU TLV type.
            /// </summary>
            internal const uint TagType = 0x200;
        }

        internal static class AggregationRequestPayload

        {
            /// <summary>
            ///     Aggregation request TLV type.
            /// </summary>
            internal const uint TagType = 0x201;

            internal const uint RequestIdTagType = 0x1;
            internal const uint RequestHashTagType = 0x2;
            internal const uint RequestLevelTagType = 0x3;
            internal const uint ConfigTagType = 0x10;
        }

        internal static class AggregationResponsePayload
        {
            /// <summary>
            ///     Aggregation response payload TLV type.
            /// </summary>
            internal const uint TagType = 0x202;

            internal const uint RequestIdTagType = 0x1;
            internal const uint ConfigTagType = 0x10;
            internal const uint RequestAcknowledgmentTagType = 0x11;
        }

        internal static class ExtendErrorPayload
        {
            /// <summary>
            ///     Extension error payload TLV type.
            /// </summary>
            internal const uint TagType = 0x303;
        }

        internal static class ExtendPdu
        {
            /// <summary>
            ///     Extension PDU TLV type.
            /// </summary>
            internal const uint TagType = 0x300;
        }

        internal static class ExtendRequestPayload
        {
            /// <summary>
            ///     Extend request payload TLV type.
            /// </summary>
            internal const uint TagType = 0x301;

            internal const uint RequestIdTagType = 0x1;
            internal const uint AggregationTimeTagType = 0x2;
            internal const uint PublicationTimeTagType = 0x3;
        }

        internal static class ExtendResponsePayload
        {
            /// <summary>
            ///     Extension response payload TLV type.
            /// </summary>
            internal const uint TagType = 0x302;

            internal const uint RequestIdTagType = 0x1;
            internal const uint LastTimeTagType = 0x10;
        }

        internal static class KsiPduHeader
        {
            /// <summary>
            ///     KSI PDU header TLV type.
            /// </summary>
            internal const uint TagType = 0x1;

            internal const uint LoginIdTagType = 0x1;
            internal const uint InstanceIdTagType = 0x2;
            internal const uint MessageIdTagType = 0x3;
        }

        internal static class AggregationAuthenticationRecord
        {
            /// <summary>
            ///     Aggregation authentication record tag type
            /// </summary>
            internal const uint TagType = 0x804;

            internal const uint AggregationTimeTagType = 0x2;
            internal const uint ChainIndexTagType = 0x3;
            internal const uint InputHashTagType = 0x5;
        }

        internal static class AggregationHashChain
        {
            /// <summary>
            ///     Aggregation hash chain TLV type.
            /// </summary>
            internal const uint TagType = 0x801;

            internal const uint AggregationTimeTagType = 0x2;
            internal const uint ChainIndexTagType = 0x3;
            internal const uint InputDataTagType = 0x4;
            internal const uint InputHashTagType = 0x5;
            internal const uint AggregationAlgorithmIdTagType = 0x6;

            internal static class Link
            {
                internal const uint LevelCorrectionTagType = 0x1;
                internal const uint SiblingHashTagType = 0x2;
                internal const uint MetaHashTagType = 0x3;
            }

            internal static class MetaData
            {
                /// <summary>
                ///     Metadata TLV type.
                /// </summary>
                // ReSharper disable once MemberHidesStaticFromOuterClass
                internal const uint TagType = 0x4;

                internal const uint ClientIdTagType = 0x1;
                internal const uint MachineIdTagType = 0x2;
                internal const uint SequenceNumberTagType = 0x3;
                internal const uint RequestTimeTagType = 0x4;
            }
        }

        internal static class CalendarAuthenticationRecord
        {
            /// <summary>
            ///     Calendar authentication record TLV type
            /// </summary>
            internal const uint TagType = 0x805;
        }

        internal static class CalendarHashChain
        {
            /// <summary>
            ///     Calendar hash chain tag type
            /// </summary>
            internal const uint TagType = 0x802;

            internal const uint PublicationTimeTagType = 0x1;
            internal const uint AggregationTimeTagType = 0x2;
            internal const uint InputHashTagType = 0x5;
        }

        internal static class KsiSignature
        {
            /// <summary>
            ///     KSI signature tag type
            /// </summary>
            internal const uint TagType = 0x800;
        }

        internal static class Rfc3161Record
        {
            /// <summary>
            ///     RFC3161 record tag type
            /// </summary>
            internal const uint TagType = 0x806;

            internal const uint AggregationTimeTagType = 0x2;
            internal const uint ChainIndexTagType = 0x3;
            internal const uint InputHashTagType = 0x5;
            internal const uint TstInfoPrefixTagType = 0x10;
            internal const uint TstInfoSuffixTagType = 0x11;
            internal const uint TstInfoAlgorithmTagType = 0x12;
            internal const uint SignedAttributesPrefixTagType = 0x13;
            internal const uint SignedAttributesSuffixTagType = 0x14;
            internal const uint SignedAttributesAlgorithmTagType = 0x15;
        }
    }
}