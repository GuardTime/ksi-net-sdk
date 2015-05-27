using System;
using System.IO;

namespace Guardtime.KSI.Parser
{
    public class TlvWriter : BinaryWriter
    {
        public TlvWriter(Stream input) : base(input)
        {
        }

        public void WriteTag(TlvTag tag) {
            // TODO: What to do on null tag, exception or skip?
            if (tag == null)
            {
                return;
            }

            if (tag.Type > TlvReader.MaxType)
            {
                throw new ArgumentOutOfRangeException("tag");
            }

            byte[] data = tag.EncodeValue();
            bool tlv16 = tag.Type > TlvReader.TypeMask
                    || (data != null && data.Length > byte.MaxValue);
            byte firstByte = (byte)((tlv16 ? TlvReader.Tlv16Flag : 0)
                                     + (tag.NonCritical ? TlvReader.NonCriticalFlag : 0)
                                     + (tag.Forward ? TlvReader.ForwardFlag : 0));

            if (tlv16)
            {
                firstByte = (byte)(firstByte
                                    | (tag.Type >> TlvReader.ByteBits) & TlvReader.TypeMask);
                Write(firstByte);
                Write((byte)tag.Type);
                if (data == null)
                {
                    Write((byte)0);
                }
                else
                {
                    if (data.Length > ushort.MaxValue)
                    {
                        throw new ArgumentOutOfRangeException("tag");
                    }
                    Write((byte)(data.Length >> TlvReader.ByteBits));
                    Write((byte)data.Length);
                    Write(data);
                }
            }
            else
            {
                firstByte = (byte)(firstByte | tag.Type & TlvReader.TypeMask);
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
