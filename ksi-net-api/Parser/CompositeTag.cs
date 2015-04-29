
using System;
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
            using (var stream = new MemoryStream(valueBytes))
            {
                using (var tlvReader = new TlvReader(stream))
                {
                    while (tlvReader.BaseStream.Position < tlvReader.BaseStream.Length)
                    {
                        var tag = tlvReader.ReadTag();
                        
                        var resultMember = GetMember(tag);
                        if (resultMember == null)
                        {
                            if (!tag.NonCritical)
                            {
                                // TODO: Create correct handling
                                throw new Exception("BROKEN STRUCTURE");
                            }

                            resultMember = tag;
                        }

                        Value.Add(resultMember);
                    }
                }
            }
        }

        public sealed override byte[] EncodeValue()
        {
            return new byte[] {0x2, 0x0};
        }

        public abstract ITlvTag GetMember(ITlvTag tag);

        public sealed override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append(base.ToString()).Append('\n');

            foreach (var tag in Value)
            {
                builder.Append(TabPrefix(tag.ToString()));
                builder.Append("\n");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected string TabPrefix(string s) {
            var builder = new StringBuilder();
            
            var lines = s.Split('\n');
            foreach (var str in lines)
            {
                builder.Append("  ");
                builder.Append(str);
                if (!str.Equals(lines[lines.Length - 1])) {
                    builder.Append("\n");
                }
            }

            return builder.ToString();
        }
    }

}
