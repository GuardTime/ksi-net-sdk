using System;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public abstract class TlvTag
    {
        private readonly uint _type;
        private readonly bool _nonCritical;
        private readonly bool _forward;

        /// <summary>
        /// Tlv tag type.
        /// </summary>
        public uint Type
        {
            get { return _type; }
        }

        /// <summary>
        /// Is tlv tag non critical.
        /// </summary>
        public bool NonCritical
        {
            get { return _nonCritical; }
        }

        /// <summary>
        /// Is tlv forwarded.
        /// </summary>
        public bool Forward
        {
            get { return _forward; }
        }

        protected TlvTag(uint type, bool nonCritical, bool forward)
        {
            _type = type;
            _nonCritical = nonCritical;
            _forward = forward;
        }

        protected TlvTag(TlvTag tag)
        {
            if (tag == null)
            {
                throw new ArgumentNullException("tag");
            }

            _type = tag.Type;
            _nonCritical = tag.NonCritical;
            _forward = tag.Forward;
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
            builder.Append("0x").Append(Util.Util.ConvertByteArrayToString(EncodeValue()));

            return builder.ToString();
        }
    }

}
