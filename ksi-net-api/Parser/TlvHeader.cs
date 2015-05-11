using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Parser
{
    public class TlvHeader
    {
        /// <summary>
        /// Tlv tag type.
        /// </summary>
        public uint Type { get; set; }
        /// <summary>
        /// Is tlv tag non critical.
        /// </summary>
        public bool NonCritical { get; set; }
        /// <summary>
        /// Is tlv forwarded.
        /// </summary>
        public bool Forward { get; set; }

        public TlvHeader(uint type, bool nonCritical, bool forward)
        {
            Type = type;
            Forward = forward;
            NonCritical = nonCritical;
        }
    }
}
