using System;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Specialized reader for decoding TLV data.
    /// </summary>
    public class TlvReader : BinaryReader
    {
        public const byte Tlv16Flag = 0x80;
        public const byte NonCriticalFlag = 0x40;
        public const byte ForwardFlag = 0x20;

        public const byte TypeMask = 0x1f;
        public const ushort MaxType = 0x1fff;

        public const byte ByteBits = 8;

        /// <summary>
        /// Reads from given input stream for TLV data.
        /// </summary>
        /// <param name="input">input stream to read data from</param>
        public TlvReader(Stream input) : base(input)
        {
        }

        /// <summary>
        /// Reads from given input stream with specified encoding for TLV data.
        /// </summary>
        /// <param name="input">input stream to read data from</param>
        /// <param name="encoding">data encoding</param>
        public TlvReader(Stream input, Encoding encoding) : base(input, encoding)
        {
        }

        public TlvTag ReadTag()
        {
            return ReadTag(null);
        }

        /// <summary>
        /// Reads a complete TLV item from the wrapped stream.
        /// </summary>
        /// <returns>raw tlv tag</returns>
        public TlvTag ReadTag(TlvTag parent) {
            try {
                byte firstByte = ReadByte();

                bool tlv16 = (firstByte & Tlv16Flag) != 0;
                bool nonCritical = (firstByte & NonCriticalFlag) != 0;
                bool forward = (firstByte & ForwardFlag) != 0;

                uint type = (uint) (firstByte & TypeMask);
                ushort length;
                
                if (tlv16) {
                    byte typeLsb = ReadByte();
                    type = (type << ByteBits) | typeLsb;
                    length = (ushort)((ReadByte() << ByteBits) | ReadByte());
                } else {
                    length = ReadByte();
                }

                byte[] data = new byte[length];
                Read(data, 0, length);

                return new RawTag(parent, type, nonCritical, forward, data);
            } catch (EndOfStreamException e) {
                throw new FormatException("Premature end of data", e);
            }
        }
    }
}
