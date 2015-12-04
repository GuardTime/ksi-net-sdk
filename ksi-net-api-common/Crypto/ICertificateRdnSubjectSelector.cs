namespace Guardtime.KSI.Crypto
{
    public interface ICertificateRdnSubjectSelector
    {
        bool Match(object obj);
    }
}