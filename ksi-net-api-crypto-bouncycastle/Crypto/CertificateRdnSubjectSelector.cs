using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Guardtime.KSI.Crypto
{
    public class CertificateRdnSubjectSelector : ICertificateRdnSubjectSelector
    {

        private readonly X509Name _subjectDn;

        // TODO: If empty allow everything?
        public CertificateRdnSubjectSelector(Dictionary<string, string> subjectDn)
        {
            List<DerObjectIdentifier> oidList = new List<DerObjectIdentifier>();
            List<string> valueList = new List<string>();

            if (subjectDn != null)
            {
                foreach (KeyValuePair<string, string> dn in subjectDn)
                {
                    oidList.Add(new DerObjectIdentifier(dn.Key));
                    valueList.Add(dn.Value);
                }
            }
            _subjectDn = new X509Name(oidList, valueList);
        }

        public CertificateRdnSubjectSelector(string subjectDn)
        {
            if (string.IsNullOrEmpty(subjectDn))
            {
                throw new ArgumentException("Value cannot be empty", nameof(subjectDn));
            }

            _subjectDn = new X509Name(subjectDn);
        }

        public bool Match(object obj)
        {
            return Match(obj as X509Certificate);
        }

        public bool Match(X509Certificate certificate)
        {
            if (certificate == null)
            {
                return false;
            }


            IList subjectDnOidList = _subjectDn.GetOidList();

            for (int i = 0; i < subjectDnOidList.Count; i++)
            {
                if (!Contains(_subjectDn.GetValueList()[i], certificate.SubjectDN.GetValueList((DerObjectIdentifier)subjectDnOidList[i])))
                {
                    return false;
                }
            }


            return true;
        }

        private static bool Contains(object searchValue, IList certificateValueList)
        {
            if (certificateValueList == null)
            {
                return false;
            }

            if (searchValue == null)
            {
                return true;
            }

            
            foreach (object value in certificateValueList)
            {
                if (value.Equals(searchValue))
                {
                    return true;
                }
            }

            return false;
        }
    }
}