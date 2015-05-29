using System;
using System.CodeDom;
using System.IO;
using System.Net;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service
{
    // TODO: Better names
    public class HttpAggregationRequest : IAsyncResult
    {

        public delegate void Test();

        public void Proov()
        {
            
        }

        public HttpAggregationRequest()
        {
            WebRequest request = WebRequest.Create("http://ksigw.test.guardtime.com:3333/gt-signingservice");
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            AggregationPdu tag = new AggregationPdu();

            byte[] data = tag.Encode();
            request.ContentLength = data.Length; 
            Stream stream = request.GetRequestStream();
            stream.Write(data, 0, data.Length);
            stream.Close();
            Console.WriteLine(tag);
            Console.WriteLine();
            try
            {
                //TODO: Check java api response handling, KSISignatureDO when handles list then skips unnessessary tags, in other constructors will give error
                using (Stream s = request.GetResponse().GetResponseStream())
                using (TlvReader reader = new TlvReader(s))
                {
                    AggregationPdu response = new AggregationPdu(reader.ReadTag());
                    // TODO: Check structure
                    //                    response.IsValidStructure();
                    // TODO: Create signature from payload, remove unwanted tags and check if payload is correct
                    AggregationResponsePayload responsePayload = response.Payload as AggregationResponsePayload;
                    if (responsePayload == null)
                    {
                        throw new KsiException("Invalid aggregation response with http code 200");
                    }

                    KsiSignature signature = new KsiSignature(responsePayload);
                    Console.WriteLine(signature);
                }
            }
            catch (WebException e)
            {
                using (Stream s = e.Response.GetResponseStream())
                using (TlvReader reader = new TlvReader(s))
                {
                    Console.WriteLine(new AggregationPdu(reader.ReadTag()));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            
        }

        public bool IsCompleted { get; private set; }
        public WaitHandle AsyncWaitHandle { get; private set; }
        public object AsyncState { get; private set; }
        public bool CompletedSynchronously { get; private set; }
    }
}
