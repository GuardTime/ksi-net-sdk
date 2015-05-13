using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class CompositeTag : TlvTag
    {
        protected new List<TlvTag> Value;

        public CompositeTag(byte[] bytes) : base(bytes)
        {
            DecodeValue(base.EncodeValue());
        }

        public CompositeTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        private void DecodeValue(byte[] bytes)
        {
            Value = new List<TlvTag>();

            using (var tlvReader = new TlvReader(new MemoryStream(bytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    Value.Add(tlvReader.ReadTag());
                }
            }
        }

        public override byte[] EncodeValue()
        {
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    writer.WriteTag(Value[i]);
                }

                return ((MemoryStream)writer.BaseStream).ToArray();
            }
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

            builder.Append("]:").Append('\n');

            for (var i = 0; i < Value.Count; i++)
            {
                builder.Append(TabPrefix(Value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s)
        {
            var builder = new StringBuilder();

            var lines = s.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (!lines[i].Equals(lines[lines.Length - 1]))
                {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }

    }

}
