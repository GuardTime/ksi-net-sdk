using System;
using System.Text;

namespace Guardtime.KSI.Parser
{ 
 
    public class TlvElement
    {
        public uint Type { get; set; }
        public bool NonCritical { get; set; }
        public bool Forward { get; set; }
        public ITlvContent Value { get; set; }

        public TlvElement(uint type, bool nonCritical, bool forward, ITlvContent value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            Type = type;
            NonCritical = nonCritical;
            Forward = forward;
            Value = value;
        }
    }
}
