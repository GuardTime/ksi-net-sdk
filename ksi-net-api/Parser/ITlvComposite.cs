namespace Guardtime.KSI.Parser
{
    public interface ITlvComposite
    {

        ITlvContent GetMember(uint type, byte[] valueBytes);
    }
}