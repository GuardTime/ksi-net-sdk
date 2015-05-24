using System;
using System.IO;
using System.Net;
using Guardtime.KSI.Parser;

namespace Guardtime.KSI.Service
{
    // TODO: Better names
    public class HttpAggregationRequest
    {
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
            try
            {
                //TODO: Check java api response handling, KSISignatureDO when handles list then skips unnessessary tags, in other cases will give error
                using (Stream s = request.GetResponse().GetResponseStream())
                {
                    MemoryStream memoryStream = new MemoryStream();
                    byte[] buffer = new byte[8092];
                    int length;
                    while ((length = s.Read(buffer, 0, 8092)) > 0)
                    {
                        memoryStream.Write(buffer, 0, length);
                    }


                    byte[] dataResponse = memoryStream.ToArray();
                    s.Read(dataResponse, 0, dataResponse.Length);
                    Console.WriteLine(new AggregationPdu(dataResponse));
                }
            }
            catch (WebException e)
            {
                using (Stream s = e.Response.GetResponseStream())
                {
                    byte[] dataResponse = new byte[s.Length];
                    s.Read(dataResponse, 0, dataResponse.Length);
                    Console.WriteLine(new AggregationPdu(dataResponse));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            
        }
    }
}
