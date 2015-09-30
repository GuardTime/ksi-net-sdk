namespace Guardtime.KSI.Parser
{
    /// <summary>
    ///     TLV objects base class.
    /// </summary>
    public interface ITlvTag
    {
        /// <summary>
        ///     Tlv tag type.
        /// </summary>
        uint Type { get; }

        /// <summary>
        ///     Is tlv tag non critical.
        /// </summary>
        bool NonCritical { get; }

        /// <summary>
        ///     Is tlv forwarded.
        /// </summary>
        bool Forward { get; }

        /// <summary>
        ///     Encode TLV object value.
        /// </summary>
        /// <returns>TLV object value as bytes</returns>
        byte[] EncodeValue();
    }
}