using System;
using System.Text;

namespace Guardtime.KSI.Parse
{
    public class TlvElement
    {
        /// <summary>
        /// Tlv tag type.
        /// </summary>
        public uint Type { get; set; }
        /// <summary>
        /// Is tlv tag non critical.
        /// </summary>
        public bool NonCritical { get; set; }
        /// <summary>
        /// Is tlv forwarded.
        /// </summary>
        public bool Forward { get; set; }
        /// <summary>
        /// Tlv content.
        /// </summary>
        public ITlvContent Content { get; set; }

        public TlvElement(uint type, bool nonCritical, bool forward, ITlvContent content)
        {
            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Content = content;
        }

        public TlvElement(byte[] bytes)
        {
            Content = Parse(bytes);
        }

        private ITlvContent Parse(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 2)
            {
                throw new FormatException("Invalid TLV bytes");
            }
                
            var firstByte = bytes[0];

            NonCritical = (firstByte & TlvReader.NonCriticalFlag) != 0;
            Forward = (firstByte & TlvReader.ForwardFlag) != 0;
            Type = (uint)(firstByte & TlvReader.TypeMask);

            var tlv16 = (firstByte & TlvReader.Tlv16Flag) != 0;
            ushort length;
            byte[] data;

            if (tlv16)
            {
                if (bytes.Length < 4)
                {
                    throw new FormatException("Premature end of data");
                }
                var typeLsb = bytes[1];
                Type = typeLsb | (Type << TlvReader.ByteBits);
                length = (ushort)((bytes[2] << TlvReader.ByteBits) | bytes[3]);
                if (bytes.Length < length + 4)
                {
                    throw new FormatException("Premature end of data");
                }
                data = new byte[length];
                Array.Copy(bytes, 4, data, 0, length);
            }
            else
            {
                length = bytes[1];
                data = new byte[length];
                if (bytes.Length < length + 2)
                {
                    throw new FormatException("Premature end of data");
                }
                Array.Copy(bytes, 2, data, 0, length);
            }
            
            return new BinaryContent(data);
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append("TLV[0x").Append(Type.ToString("X"));

            if (NonCritical)
            {
                builder.Append(",N");
            }

            if (Forward)
            {
                builder.Append(",F");
            }

            builder.Append("]:");

            builder.Append(Content);

            return builder.ToString();
        }
    }

}
