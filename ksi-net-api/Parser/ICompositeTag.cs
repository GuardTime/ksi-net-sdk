namespace Guardtime.KSI.Parser
{
    public interface ICompositeTag
    {
        ITlvTag GetMember(ITlvTag tag);
    }
}
