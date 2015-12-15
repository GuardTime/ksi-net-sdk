using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Crypto
{
    /// <summary>
    /// Certificate subject rdn
    /// </summary>
    public class CertificateSubjectRdn
    {
        /// <summary>
        /// Create Certificate subject rdn instance
        /// </summary>
        /// <param name="oid"></param>
        /// <param name="value"></param>
        public CertificateSubjectRdn(string oid, string value)
        {
            Oid = oid;
            Value = value;
        }

        public string Oid { get; set; }
        public string Value { get; set; }
    }
}