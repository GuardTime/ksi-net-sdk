using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public abstract class CompositeTag : TlvTag
    {
        // TODO: Make list thread safe
        public List<TlvTag> Value;
        // TODO: Create possibility to check composite tag validity

        protected CompositeTag(byte[] bytes) : base(bytes)
        {
            DecodeValue(ValueBytes);
        }

        protected CompositeTag(TlvTag tag) : base(tag)
        {
            DecodeValue(tag.EncodeValue());
        }

        protected CompositeTag(uint type, bool nonCritical, bool forward) : base(type, nonCritical, forward, new byte[] {})
        {
            Value = new List<TlvTag>();
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

        public abstract bool IsValidStructure(); 

        public override bool Equals(object obj)
        {
            var tag = obj as CompositeTag;
            if (tag == null || (tag.Type != Type && tag.Forward != Forward && tag.NonCritical != NonCritical))
            {
                return false;
            }
            
            var tagEnumerator = tag.Value == null ? (IEnumerator) new Util.EmptyEnumerator() : tag.Value.GetEnumerator();
            var enumerator = Value == null ? (IEnumerator)new Util.EmptyEnumerator() : Value.GetEnumerator();
            var match = true;
            while (match && tagEnumerator.MoveNext() && enumerator.MoveNext())
            {
                var value1 = tagEnumerator.Current;
                var value2 = enumerator.Current;
                match = value1 == null ? value2 == null : value1.Equals(value2);
            }

            return match;
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
