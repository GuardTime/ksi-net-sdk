namespace Guardtime.KSI.Crypto
{
    public interface ICertificateSubjectRdnSelector
    {
        bool Match(object obj);
    }
}