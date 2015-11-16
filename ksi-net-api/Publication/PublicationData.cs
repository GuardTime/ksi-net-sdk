using System;
using System.Collections.Generic;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Publication
{
    /// <summary>
    ///     Publication data TLV element.
    /// </summary>
    public sealed class PublicationData : CompositeTag
    {
        /// <summary>
        ///     Publication data tag type.
        /// </summary>
        public const uint TagType = 0x10;

        private const uint PublicationTimeTagType = 0x2;
        private const uint PublicationHashTagType = 0x4;
        private readonly ImprintTag _publicationHash;

        private readonly IntegerTag _publicationTime;

        /// <summary>
        ///     Create new publication data TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails</exception>
        public PublicationData(TlvTag tag) : base(tag)
        {
            if (Type != TagType)
            {
                throw new TlvException("Invalid publication data type(" + Type + ").");
            }

            int publicationTimeCount = 0;
            int publicationHashCount = 0;

            for (int i = 0; i < Count; i++)
            {
                switch (this[i].Type)
                {
                    case PublicationTimeTagType:
                        _publicationTime = new IntegerTag(this[i]);
                        publicationTimeCount++;
                        break;
                    case PublicationHashTagType:
                        _publicationHash = new ImprintTag(this[i]);
                        publicationHashCount++;
                        break;
                    default:
                        VerifyCriticalFlag(this[i]);
                        break;
                }
            }

            if (publicationTimeCount != 1)
            {
                throw new TlvException("Only one publication time must exist in publication data.");
            }

            if (publicationHashCount != 1)
            {
                throw new TlvException("Only one publication hash must exist in publication data.");
            }
        }

        /// <summary>
        ///     Create new publication data TLV element from publication time and publication hash.
        /// </summary>
        /// <param name="publicationTime">publication time</param>
        /// <param name="publicationHash">publication hash</param>
        public PublicationData(ulong publicationTime, DataHash publicationHash)
            : base(TagType, false, true, new List<TlvTag>()
            {
                new IntegerTag(PublicationTimeTagType, false, false, publicationTime),
                new ImprintTag(PublicationHashTagType, false, false, publicationHash)
            })
        {
            _publicationTime = (IntegerTag)this[0];
            _publicationHash = (ImprintTag)this[1];
        }

        /// <summary>
        ///     Create new publication data TLV element from publication string.
        /// </summary>
        /// <param name="publicationString">publication string</param>
        /// <exception cref="TlvException">thrown when TLV parsing fails from publication string</exception>
        public PublicationData(string publicationString) : base(TagType, false, true, DecodePublicationString(publicationString))
        {
            _publicationTime = (IntegerTag)this[0];
            _publicationHash = (ImprintTag)this[1];
        }

        private static List<TlvTag> DecodePublicationString(string publicationString)
        {
            if (publicationString == null)
            {
                throw new TlvException("Invalid publication string: null.");
            }

            byte[] dataBytesWithCrc32 = Base32.Decode(publicationString);

            // Length needs to be at least 13 bytes (8 bytes for time plus non-empty hash imprint plus 4 bytes for crc32)
            if (dataBytesWithCrc32 == null || dataBytesWithCrc32.Length < 13)
            {
                throw new TlvException("Publication string base 32 decode failed.");
            }

            byte[] dataBytes = new byte[dataBytesWithCrc32.Length - 4];
            Array.Copy(dataBytesWithCrc32, 0, dataBytes, 0, dataBytesWithCrc32.Length - 4);

            byte[] computedCrc32 = Util.EncodeUnsignedLong(Crc32.Calculate(dataBytes, 0));
            byte[] messageCrc32 = new byte[4];
            Array.Copy(dataBytesWithCrc32, dataBytesWithCrc32.Length - 4, messageCrc32, 0, 4);
            if (!Util.IsArrayEqual(computedCrc32, messageCrc32))
            {
                throw new TlvException("Publication string CRC 32 check failed.");
            }

            byte[] hashImprint = new byte[dataBytesWithCrc32.Length - 12];
            Array.Copy(dataBytesWithCrc32, 8, hashImprint, 0, dataBytesWithCrc32.Length - 12);

            byte[] publicationTimeBytes = new byte[8];
            Array.Copy(dataBytesWithCrc32, 0, publicationTimeBytes, 0, 8);

            return new List<TlvTag>()
            {
                new IntegerTag(PublicationTimeTagType, false, false, Util.DecodeUnsignedLong(publicationTimeBytes, 0, publicationTimeBytes.Length)),
                new ImprintTag(PublicationHashTagType, false, false, new DataHash(hashImprint))
            };
        } 

        /// <summary>
        ///     Get publication time.
        /// </summary>
        public ulong PublicationTime
        {
            get { return _publicationTime.Value; }
        }

        /// <summary>
        ///     Get publication hash.
        /// </summary>
        public DataHash PublicationHash
        {
            get { return _publicationHash.Value; }
        }
    }
}