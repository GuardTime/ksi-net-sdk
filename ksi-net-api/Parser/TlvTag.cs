using System;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class TlvTag
    {
        /// <summary>
        /// Tlv tag type.
        /// </summary>
        public uint Type;

        /// <summary>
        /// Is tlv tag non critical.
        /// </summary>
        public bool NonCritical;

        /// <summary>
        /// Is tlv forwarded.
        /// </summary>
        public bool Forward;

        /// <summary>
        /// Tlv content.
        /// </summary>
        public byte[] Value;

        public TlvTag(uint type, bool nonCritical, bool forward, byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Value = value;
        }

        public TlvTag(byte[] bytes)
        {
            using (var reader = new TlvReader(new MemoryStream(bytes)))
            {
                var tag = reader.ReadTag();
                Type = tag.Type;
                NonCritical = tag.NonCritical;
                Forward = tag.Forward;
                Value = tag.EncodeValue();
            }
        }

        public TlvTag(TlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            Type = tag.Type;
            NonCritical = tag.NonCritical;
            Forward = tag.Forward;
            Value = tag.EncodeValue();
        }

        public virtual byte[] EncodeValue()
        {
            return Value;
        }

        public override bool Equals(object obj)
        {
            var tag = obj as TlvTag;
            if (tag == null)
            {
                return false;
            }

            return tag.Type == Type &&
                   tag.Forward == Forward &&
                   tag.NonCritical == NonCritical &&
                   Util.Util.IsArrayEqual(tag.Value, Value);
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

            if (Value != null)
            {
                builder.Append("0x").Append(Util.Util.ConvertByteArrayToHex(EncodeValue()));
            }

            return builder.ToString();
        }
    }

}
