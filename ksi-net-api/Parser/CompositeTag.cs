using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public abstract class CompositeTag : TlvTag<List<ITlvTag>>
    {

        protected CompositeTag(ITlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        public sealed override void DecodeValue(byte[] valueBytes)
        {
            Value = new List<ITlvTag>();
            using (var tlvReader = new TlvReader(new MemoryStream(valueBytes)))
            {
                while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                {
                    Value.Add(tlvReader.ReadTag());
                }
            }
        }

        public sealed override byte[] EncodeValue()
        {
            byte[] output;
            using (var writer = new TlvWriter(new MemoryStream()))
            {
                for (var i = 0; i < Value.Count; i++)
                {
                    writer.WriteTag(Value[i]);
                }

                output = ((MemoryStream)writer.BaseStream).ToArray();
            }

            return output;
        }

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString()).Append('\n');

            for (var i = 0; i < Value.Count; i++)
            {
                builder.Append(TabPrefix(Value[i].ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s) {
            var builder = new StringBuilder();
            
            var lines = s.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (!lines[i].Equals(lines[lines.Length - 1])) {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }
        
    }
}
