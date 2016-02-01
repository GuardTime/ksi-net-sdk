using System;
using System.IO;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV object writer for stream.
    /// </summary>
    public class TlvWriter : BinaryWriter
    {
        /// <summary>
        ///     Create TLV object writer instance.
        /// </summary>
        /// <param name="input">Output stream</param>
        public TlvWriter(Stream input) : base(input)
        {
        }

        /// <summary>
        ///     Write TLV object to given stream.
        /// </summary>
        /// <param name="tag">TLV object</param>
        public void WriteTag(ITlvTag tag)
        {
            if (tag == null)
            {
                return;
            }

            WriteTag(tag, tag.Type);
        }

        /// <summary>
        ///     Write TLV object to given stream.
        /// </summary>
        /// <param name="tag">TLV object</param>
        /// <param name="tagType">TLV object type</param>
        public void WriteTag(ITlvTag tag, uint tagType)
        {
            if (tag == null)
            {
                return;
            }

            if (tagType > Constants.Tlv.MaxType)
            {
                throw new ArgumentOutOfRangeException(nameof(tag));
            }

            byte[] data = tag.EncodeValue();
            bool tlv16 = tagType > Constants.Tlv.TypeMask
                         || (data != null && data.Length > byte.MaxValue);
            byte firstByte = (byte)((tlv16 ? Constants.Tlv.Tlv16Flag : 0)
                                    + (tag.NonCritical ? Constants.Tlv.NonCriticalFlag : 0)
                                    + (tag.Forward ? Constants.Tlv.ForwardFlag : 0));

            if (tlv16)
            {
                firstByte = (byte)(firstByte
                                   | (tagType >> Constants.BitsInByte) & Constants.Tlv.TypeMask);
                Write(firstByte);
                Write((byte)tagType);
                if (data == null)
                {
                    Write((byte)0);
                }
                else
                {
                    if (data.Length > ushort.MaxValue)
                    {
                        throw new ArgumentOutOfRangeException(nameof(tag));
                    }
                    Write((byte)(data.Length >> Constants.BitsInByte));
                    Write((byte)data.Length);
                    Write(data);
                }
            }
            else
            {
                firstByte = (byte)(firstByte | tagType & Constants.Tlv.TypeMask);
                Write(firstByte);
                if (data == null)
                {
                    Write((byte)0);
                }
                else
                {
                    Write((byte)data.Length);
                    Write(data);
                }
            }
        }
    }
}