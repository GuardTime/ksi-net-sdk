using System.IO;
using System.Text;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV objects base class.
    /// </summary>
    public abstract class TlvTag : ITlvTag
    {
        private readonly bool _forward;
        private readonly bool _nonCritical;
        private readonly uint _type;

        /// <summary>
        ///     Create new TLV element from data.
        /// </summary>
        /// <param name="type">TLV element type</param>
        /// <param name="nonCritical">Is TLV element non critical</param>
        /// <param name="forward">Is TLV element forwarded</param>
        protected TlvTag(uint type, bool nonCritical, bool forward)
        {
            _type = type;
            _nonCritical = nonCritical;
            _forward = forward;
        }

        /// <summary>
        ///     Create new TLV element from TLV element.
        /// </summary>
        /// <param name="tag">TLV element</param>
        /// <exception cref="TlvException">thrown when input TLV tag is invalid.</exception>
        protected TlvTag(ITlvTag tag)
        {
            if (tag == null)
            {
                throw new TlvException("Invalid TLV tag: null.");
            }

            _type = tag.Type;
            _nonCritical = tag.NonCritical;
            _forward = tag.Forward;
        }

        /// <summary>
        ///     Tlv tag type.
        /// </summary>
        public uint Type
        {
            get { return _type; }
        }

        /// <summary>
        ///     Is tlv tag non critical.
        /// </summary>
        public bool NonCritical
        {
            get { return _nonCritical; }
        }

        /// <summary>
        ///     Is tlv forwarded.
        /// </summary>
        public bool Forward
        {
            get { return _forward; }
        }

        /// <summary>
        ///     Encode TLV object value.
        /// </summary>
        /// <returns>TLV object value as bytes</returns>
        public abstract byte[] EncodeValue();

        /// <summary>
        ///     Encode TLV object.
        /// </summary>
        /// <returns>TLV object as bytes</returns>
        public byte[] Encode()
        {
            MemoryStream stream = null;
            try
            {
                stream = new MemoryStream();
                using (TlvWriter writer = new TlvWriter(stream))
                {
                    stream = null;
                    writer.WriteTag(this);
                    return ((MemoryStream) writer.BaseStream).ToArray();
                }
            }
            finally
            {
                if (stream != null)
                {
                    stream.Dispose();
                }
            }
        }

        /// <summary>
        ///     Convert TLV object to string.
        /// </summary>
        /// <returns>TLV object as string</returns>
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
            builder.Append("0x").Append(Base16.Encode(EncodeValue()));

            return builder.ToString();
        }
    }
}