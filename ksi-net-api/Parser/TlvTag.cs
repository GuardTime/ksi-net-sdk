using System;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public abstract class TlvTag
    {
        private TlvTag _parent;

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
        protected byte[] Value;

        protected TlvTag(TlvTag parent, uint type, bool nonCritical, bool forward, byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            _parent = parent;
            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Value = value;
        }

        protected TlvTag(TlvTag parent, byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            using (MemoryStream stream = new MemoryStream(bytes))
            using (TlvReader reader = new TlvReader(stream))
            {
                TlvTag tag = reader.ReadTag();
                _parent = parent;
                Type = tag.Type;
                NonCritical = tag.NonCritical;
                Forward = tag.Forward;
                Value = tag.EncodeValue();
            }
        }

        protected TlvTag(TlvTag parent, TlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            _parent = parent;
            Type = tag.Type;
            NonCritical = tag.NonCritical;
            Forward = tag.Forward;
            Value = tag.EncodeValue();
        }

        public abstract byte[] EncodeValue();

        public byte[] Encode()
        {
            using (MemoryStream stream = new MemoryStream())
            using (TlvWriter writer = new TlvWriter(stream))
            {
                writer.WriteTag(this);
                return stream.ToArray();
            }
        }
        

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
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

            builder.Append("0x").Append(Util.Util.ConvertByteArrayToHex(EncodeValue()));

            return builder.ToString();
        }
    }

}
