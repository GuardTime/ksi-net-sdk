using System;
using System.Text;

namespace Guardtime.KSI.Parse
{
    public class TlvComposite : TlvElement
    {

        private CompositeContent _content;

        /// <summary>
        /// Tlv content.
        /// </summary>
        public new CompositeContent Content {
            get { return _content; }
            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                _content = value;
                base.Content = value;
            }
        }

        public TlvComposite(uint type, bool nonCritical, bool forward, CompositeContent content) : base(type, nonCritical, forward, content)
        {
            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Content = content;
        }

        public TlvComposite(byte[] bytes) : base(bytes)
        {
            Content = new CompositeContent(base.Content.EncodeValue());
        }

        
    }

}
