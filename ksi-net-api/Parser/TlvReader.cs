using System;
using System.IO;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Specialized reader for decoding TLV data.
    /// </summary>
    public class TlvReader : BinaryReader
    {
        /// <summary>
        /// TLV element 16 bit flag
        /// </summary>
        public const byte Tlv16Flag = 0x80;
        /// <summary>
        /// TLV element non critical flag
        /// </summary>
        public const byte NonCriticalFlag = 0x40;
        /// <summary>
        /// TLV element forward flag
        /// </summary>
        public const byte ForwardFlag = 0x20;

        /// <summary>
        /// TLV element type mask.
        /// </summary>
        public const byte TypeMask = 0x1f;
        /// <summary>
        /// TLV element max type.
        /// </summary>
        public const ushort MaxType = 0x1fff;

        /// <summary>
        /// Bits in byte
        /// </summary>
        public const byte ByteBits = 8;

        /// <summary>
        /// Reads from given input stream for TLV data.
        /// </summary>
        /// <param name="input">input stream to read data from</param>
        public TlvReader(Stream input) : base(input)
        {
        }

        /// <summary>
        /// Reads a complete TLV item from the wrapped stream.
        /// </summary>
        /// <returns>raw tlv tag</returns>
        public TlvTag ReadTag() {
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
                int bytesRead = Read(data, 0, length);

                if (bytesRead != length)
                {
                    throw new EndOfStreamException("Could not read TLV data with expected length of " + length + ", instead could only read " + bytesRead);
                }

                return new RawTag(type, nonCritical, forward, data);
            } catch (EndOfStreamException e) {
                // TODO: Throw better exception

                throw new FormatException("Premature end of data", e);
            }
        }
    }
}
