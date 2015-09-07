using System;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using System.Threading;
using System.IO;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Service
{
    // TODO: Implement timeout
    /// <summary>
    /// KSI service.
    /// </summary>
    public class KsiService : IKsiService
    {
        private readonly IKsiSigningServiceProtocol _sigingServiceProtocol;
        private readonly IKsiExtendingServiceProtocol _extendingServiceProtocol;
        private readonly IKsiPublicationsFileServiceProtocol _publicationsFileServiceProtocol;
        private readonly IKsiServiceSettings _serviceSettings;
        private readonly PublicationsFileFactory _publicationsFileFactory;

        /// <summary>
        /// Create KSI service with service protocol and service settings.
        /// </summary>
        /// <param name="signingServiceProtocol">signing service protocol</param>
        /// <param name="extendingServiceProtocol">extending service protocol</param>
        /// <param name="publicationsFileServiceProtocol">publications file protocol</param>
        /// <param name="serviceSettings">service settings</param>
        /// <param name="publicationsFileFactory">publications file factory</param>
        public KsiService(  IKsiSigningServiceProtocol signingServiceProtocol, 
                            IKsiExtendingServiceProtocol extendingServiceProtocol,
                            IKsiPublicationsFileServiceProtocol publicationsFileServiceProtocol,                
                            IKsiServiceSettings serviceSettings,
                            PublicationsFileFactory publicationsFileFactory)
        {
            if (serviceSettings == null)
            {
                throw new ArgumentNullException("serviceSettings");
            }

            if (publicationsFileFactory == null)
            {
                throw new ArgumentNullException("publicationsFileFactory");
            }

            _sigingServiceProtocol = signingServiceProtocol;
            _extendingServiceProtocol = extendingServiceProtocol;
            _publicationsFileServiceProtocol = publicationsFileServiceProtocol;
            _serviceSettings = serviceSettings;
            _publicationsFileFactory = publicationsFileFactory;
        }


        /// <summary>
        /// Sync create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>KSI signature</returns>
        public KsiSignature Sign(DataHash hash)
        {
            return EndSign(BeginSign(hash, null, null));
        }

        /// <summary>
        /// Async begin create signature with given data hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginSign(DataHash hash, AsyncCallback callback, object asyncState)
        {
            if (_sigingServiceProtocol == null)
            {
                throw new InvalidOperationException("Signing service protocol is missing from service");    
            }

            AggregationPdu pdu = new AggregationPdu(new KsiPduHeader(_serviceSettings.LoginId), new AggregationRequestPayload(hash));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _sigingServiceProtocol.BeginSign(pdu.Encode(), callback, asyncState);
            return new CreateSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// Async end create signature.
        /// </summary>
        /// <param name="asyncResult">async result status</param>
        /// <returns>KSI signature</returns>
        public KsiSignature EndSign(IAsyncResult asyncResult)
        {
            if (_sigingServiceProtocol == null)
            {
                throw new InvalidOperationException("Signing service protocol is missing from service");
            }

            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }

            KsiServiceAsyncResult serviceAsyncResult = asyncResult as CreateSignatureKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _sigingServiceProtocol.EndSign(serviceAsyncResult.ServiceProtocolAsyncResult);
            using (MemoryStream memoryStream = new MemoryStream(data))
            using (TlvReader reader = new TlvReader(memoryStream))
            {
                AggregationPdu tag = new AggregationPdu(reader.ReadTag());
                return new KsiSignature(tag.Payload);
            }
        }

        /// <summary>
        /// Sync extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature Extend(KsiSignature signature)
        {
            return EndExtend(BeginExtend(signature, null, null));
        }

        /// <summary>
        /// Sync extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature Extend(KsiSignature signature, PublicationRecord publicationRecord)
        {
            return EndExtend(BeginExtend(signature, publicationRecord, null, null));
        }

        /// <summary>
        /// Async begin extend signature to latest publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(KsiSignature signature, AsyncCallback callback, object asyncState)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new InvalidOperationException("Extending service protocol is missing from service");
            }

            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChain = signature.GetAggregationHashChains();
            ExtendPdu pdu = new ExtendPdu(new KsiPduHeader(_serviceSettings.LoginId), new ExtendRequestPayload(aggregationHashChain[aggregationHashChain.Count - 1].AggregationTime));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), callback, asyncState);
            return new ExtendSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, signature, asyncState);
        }

        /// <summary>
        /// Async begin extend signature to given publication.
        /// </summary>
        /// <param name="signature">KSI signature</param>
        /// <param name="publicationRecord">publication record</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginExtend(KsiSignature signature, PublicationRecord publicationRecord, AsyncCallback callback, object asyncState)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new InvalidOperationException("Extending service protocol is missing from service");
            }

            if (signature == null)
            {
                throw new ArgumentNullException("signature");
            }

            ReadOnlyCollection<AggregationHashChain> aggregationHashChain = signature.GetAggregationHashChains();
            // TODO: Set publication to payload
            ExtendPdu pdu = new ExtendPdu(new KsiPduHeader(_serviceSettings.LoginId), new ExtendRequestPayload(aggregationHashChain[aggregationHashChain.Count - 1].AggregationTime));
            pdu.SetMac(_serviceSettings.LoginKey);
            IAsyncResult serviceProtocolAsyncResult = _extendingServiceProtocol.BeginExtend(pdu.Encode(), callback, asyncState);
            return new ExtendSignatureKsiServiceAsyncResult(serviceProtocolAsyncResult, signature, asyncState);
        }

        /// <summary>
        /// Async end extend signature.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>extended KSI signature</returns>
        public KsiSignature EndExtend(IAsyncResult asyncResult)
        {
            if (_extendingServiceProtocol == null)
            {
                throw new InvalidOperationException("Extending service protocol is missing from service");
            }

            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }

            ExtendSignatureKsiServiceAsyncResult serviceAsyncResult = asyncResult as ExtendSignatureKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _extendingServiceProtocol.EndExtend(serviceAsyncResult.ServiceProtocolAsyncResult);

            using (MemoryStream memoryStream = new MemoryStream(data))
            using (TlvReader reader = new TlvReader(memoryStream))
            {
                ExtendPdu tag = new ExtendPdu(reader.ReadTag());

                if (tag.Payload.Type != ExtendResponsePayload.TagType) return null;

                ExtendResponsePayload payload = tag.Payload as ExtendResponsePayload;
                if (payload == null)
                {
                    // TODO: Throw correct exception
                    throw new KsiException("Invalid response payload");
                }

                return serviceAsyncResult.Signature.Extend(payload.CalendarHashChain);
            }
        }

        /// <summary>
        /// Sync get publications file.
        /// </summary>
        /// <returns>Publications file</returns>
        public PublicationsFile GetPublicationsFile()
        {
            return EndGetPublicationsFile(BeginGetPublicationsFile(null, null));
        }

        /// <summary>
        /// Async begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new InvalidOperationException("Publications file service protocol is missing from service");
            }

            IAsyncResult serviceProtocolAsyncResult = _publicationsFileServiceProtocol.BeginGetPublicationsFile(callback, asyncState);
            return new PublicationKsiServiceAsyncResult(serviceProtocolAsyncResult, asyncState);
        }

        /// <summary>
        /// Async end get publications file.
        /// </summary>
        /// <param name="asyncResult">async result</param>
        /// <returns>publications file</returns>
        public PublicationsFile EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            if (_publicationsFileServiceProtocol == null)
            {
                throw new InvalidOperationException("Publications file service protocol is missing from service");
            }

            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }

            KsiServiceAsyncResult serviceAsyncResult = asyncResult as PublicationKsiServiceAsyncResult;
            if (serviceAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("asyncResult");
            }

            if (!serviceAsyncResult.IsCompleted)
            {
                serviceAsyncResult.AsyncWaitHandle.WaitOne();
            }

            byte[] data = _publicationsFileServiceProtocol.EndGetPublicationsFile(serviceAsyncResult.ServiceProtocolAsyncResult);
            return _publicationsFileFactory.Create(data);
        }

        /// <summary>
        /// Create signature KSI service async result.
        /// </summary>
        private class CreateSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public CreateSignatureKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {

            }
        }

        /// <summary>
        /// Extend signature KSI service async result.
        /// </summary>
        private class ExtendSignatureKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            private readonly KsiSignature _signature;

            public KsiSignature Signature
            {
                get
                {
                    return _signature;
                }
            }

            public ExtendSignatureKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, KsiSignature signature, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {
                if (signature == null)
                {
                    throw new ArgumentNullException("signature");
                }

                _signature = signature;
            }
        }

        /// <summary>
        /// Publications file KSI service async result.
        /// </summary>
        private class PublicationKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public PublicationKsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState) : base(serviceProtocolAsyncResult, asyncState)
            {

            }
        }

        /// <summary>
        /// KSI service async result.
        /// </summary>
        private abstract class KsiServiceAsyncResult : IAsyncResult
        {
            private readonly object _asyncState;
            private readonly IAsyncResult _serviceProtocolAsyncResult;

            public object AsyncState
            {
                get
                {
                    return _asyncState;
                }
            }

            public WaitHandle AsyncWaitHandle
            {
                get
                {
                    return _serviceProtocolAsyncResult.AsyncWaitHandle;
                }
            }

            public bool CompletedSynchronously
            {
                get
                {
                    return _serviceProtocolAsyncResult.CompletedSynchronously;
                }
            }

            public bool IsCompleted
            {
                get
                {
                    return _serviceProtocolAsyncResult.IsCompleted;
                }
            }

            public IAsyncResult ServiceProtocolAsyncResult
            {
                get
                {
                    return _serviceProtocolAsyncResult;
                }
            }

            protected KsiServiceAsyncResult(IAsyncResult serviceProtocolAsyncResult, object asyncState)
            {
                if (serviceProtocolAsyncResult == null)
                {
                    throw new ArgumentNullException("serviceProtocolAsyncResult");
                }

                _serviceProtocolAsyncResult = serviceProtocolAsyncResult;
                _asyncState = asyncState;
            }
        }

        
    }
}
