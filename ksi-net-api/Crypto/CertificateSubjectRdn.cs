using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Certificate subject rdn component
    /// </summary>
    public class CertificateSubjectRdn
    {
        /// <summary>
        /// Create Certificate subject rdn component instance
        /// </summary>
        /// <param name="oid"></param>
        /// <param name="value"></param>
        public CertificateSubjectRdn(string oid, string value)
        {
            Oid = oid;
            Value = value;
        }

        /// <summary>
        /// Oid representing an RDN.
        /// </summary>
        public string Oid { get; set; }

        /// <summary>
        /// RDN component value.
        /// </summary>
        public string Value { get; set; }
    }
}