using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Text.RegularExpressions;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Web.Http;

namespace SteamAuth
{

    public class SteamGuardAccount
    {
        [JsonProperty("shared_secret")]
        public string SharedSecret { get; set; }

        [JsonProperty("serial_number")]
        public string SerialNumber { get; set; }

        [JsonProperty("revocation_code")]
        public string RevocationCode { get; set; }

        [JsonProperty("uri")]
        public string URI { get; set; }

        [JsonProperty("server_time")]
        public long ServerTime { get; set; }

        [JsonProperty("account_name")]
        public string AccountName { get; set; }

        [JsonProperty("token_gid")]
        public string TokenGID { get; set; }

        [JsonProperty("identity_secret")]
        public string IdentitySecret { get; set; }

        [JsonProperty("secret_1")]
        public string Secret1 { get; set; }

        [JsonProperty("status")]
        public int Status { get; set; }

        [JsonProperty("device_id")]
        public string DeviceID { get; set; }

        public string Username { get; set; }

        /// <summary>
        /// Set to true if the authenticator has actually been applied to the account.
        /// </summary>
        [JsonProperty("fully_enrolled")]
        public bool FullyEnrolled { get; set; }

        public SessionData Session { get; set; }

        private static byte[] steamGuardCodeTranslations = new byte[] { 50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89 };

        public void DeactivateAuthenticator(BCallback callback, int scheme = 2)
        {
            var postData = new Dictionary<String, String>();
            postData.Add("steamid", this.Session.SteamID.ToString());
            postData.Add("steamguard_scheme", scheme.ToString());
            postData.Add("revocation_code", this.RevocationCode);
            postData.Add("access_token", this.Session.OAuthToken);

            try
            {
                SteamWeb.MobileLoginRequest(res =>
                {
                    var removeResponse = JsonConvert.DeserializeObject<RemoveAuthenticatorResponse>(res);

                    callback(!(removeResponse == null || removeResponse.Response == null || !removeResponse.Response.Success));
                }, APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/RemoveAuthenticator/v0001", "POST", postData);
            }
            catch (Exception)
            {
                callback(false);
            }
        }

        public void GenerateSteamGuardCode(Callback callback)
        {
            TimeAligner.GetSteamTime(time =>
            {
                callback(GenerateSteamGuardCodeForTime(time));
            });
        }

        public string GenerateSteamGuardCodeForTime(long time)
        {
            if (this.SharedSecret == null || this.SharedSecret.Length == 0)
            {
                return "";
            }

            IBuffer sharedSecretArray = CryptographicBuffer.DecodeFromBase64String(this.SharedSecret);
            byte[] timeArray = new byte[8];

            time /= 30L;

            for (int i = 8; i > 0; i--)
            {
                timeArray[i - 1] = (byte)time;
                time >>= 8;
            }
            IBuffer data = CryptographicBuffer.CreateFromByteArray(timeArray);

            MacAlgorithmProvider hmacsha1 = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
            CryptographicKey hmacKey = hmacsha1.CreateKey(sharedSecretArray);

            byte[] hashedData = WindowsRuntimeBufferExtensions.ToArray(CryptographicEngine.Sign(hmacKey, data));
            byte[] codeArray = new byte[5];
            try
            {
                byte b = (byte)(hashedData[19] & 0xF);
                int codePoint = (hashedData[b] & 0x7F) << 24 | (hashedData[b + 1] & 0xFF) << 16 | (hashedData[b + 2] & 0xFF) << 8 | (hashedData[b + 3] & 0xFF);

                for (int i = 0; i < 5; ++i)
                {
                    codeArray[i] = steamGuardCodeTranslations[codePoint % steamGuardCodeTranslations.Length];
                    codePoint /= steamGuardCodeTranslations.Length;
                }
            }
            catch (Exception)
            {
                return null; //Change later, catch-alls are bad!
            }
            return Encoding.UTF8.GetString(codeArray, 0, codeArray.Length);
        }

        public void FetchConfirmations(FCCallback callback)
        {
            this.GenerateConfirmationURL(url =>
            {
                CookieContainer cookies = new CookieContainer();
                this.Session.AddCookies(cookies);

                SteamWeb.Request(response =>
                {
                    /*So you're going to see this abomination and you're going to be upset.
                      It's understandable. But the thing is, regex for HTML -- while awful -- makes this way faster than parsing a DOM, plus we don't need another library.
                      And because the data is always in the same place and same format... It's not as if we're trying to naturally understand HTML here. Just extract strings.
                      I'm sorry. */

                    Regex confIDRegex = new Regex("data-confid=\"(\\d+)\"");
                    Regex confKeyRegex = new Regex("data-key=\"(\\d+)\"");
                    Regex confDescRegex = new Regex("<div>((Confirm|Trade with|Sell -) .+)</div>");

                    if (response == null || !(confIDRegex.IsMatch(response) && confKeyRegex.IsMatch(response) && confDescRegex.IsMatch(response)))
                    {
                        if (response == null || !response.Contains("<div>Nothing to confirm</div>"))
                        {
                            throw new WGTokenInvalidException();
                        }

                        callback(new Confirmation[0]);
                        return;
                    }

                    MatchCollection confIDs = confIDRegex.Matches(response);
                    MatchCollection confKeys = confKeyRegex.Matches(response);
                    MatchCollection confDescs = confDescRegex.Matches(response);

                    List<Confirmation> ret = new List<Confirmation>();
                    for (int i = 0; i < confIDs.Count; i++)
                    {
                        string confID = confIDs[i].Groups[1].Value;
                        string confKey = confKeys[i].Groups[1].Value;
                        string confDesc = confDescs[i].Groups[1].Value;
                        Confirmation conf = new Confirmation()
                        {
                            Description = confDesc,
                            ID = confID,
                            Key = confKey
                        };
                        ret.Add(conf);
                    }

                    callback(ret.ToArray());
                }, url, "GET", null, cookies);
            });
        }

        public void AcceptConfirmation(BCallback callback, Confirmation conf)
        {
            _sendConfirmationAjax(callback, conf, "allow");
        }

        public void DenyConfirmation(BCallback callback, Confirmation conf)
        {
            _sendConfirmationAjax(callback, conf, "cancel");
        }

        /// <summary>
        /// Refreshes the Steam session. Necessary to perform confirmations if your session has expired or changed.
        /// </summary>
        /// <returns></returns>
        public void RefreshSession(BCallback callback)
        {
            string url = APIEndpoints.MOBILEAUTH_GETWGTOKEN;
            Dictionary<string, string> postData = new Dictionary<string, string>();
            postData.Add("access_token", this.Session.OAuthToken);

            SteamWeb.Request(response =>
            {
                if (response == null)
                {
                    callback(false);
                    return;
                }

                try
                {
                    var refreshResponse = JsonConvert.DeserializeObject<RefreshSessionDataResponse>(response);
                    if (refreshResponse == null || refreshResponse.Response == null || String.IsNullOrEmpty(refreshResponse.Response.Token))
                    {
                        callback(false);
                        return;
                    }

                    string token = this.Session.SteamID + "%7C%7C" + refreshResponse.Response.Token;
                    string tokenSecure = this.Session.SteamID + "%7C%7C" + refreshResponse.Response.TokenSecure;

                    this.Session.SteamLogin = token;
                    this.Session.SteamLoginSecure = tokenSecure;
                    callback(true);
                }
                catch (Exception)
                {
                    callback(false);
                }
            }, url, "POST", postData);
        }

        private void _sendConfirmationAjax(BCallback callback, Confirmation conf, string op)
        {
            GenerateConfirmationQueryParams(queryParams =>
            {
                string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/ajaxop";
                string queryString = "?op=" + op + "&";
                queryString += queryParams;
                queryString += "&cid=" + conf.ID + "&ck=" + conf.Key;
                url += queryString;

                CookieContainer cookies = new CookieContainer();
                this.Session.AddCookies(cookies);
                string referer = GenerateConfirmationURL(queryParams);

                SteamWeb.Request(response =>
                {
                    if (response == null)
                    {
                        callback(false);
                        return;
                    }

                    SendConfirmationResponse confResponse = JsonConvert.DeserializeObject<SendConfirmationResponse>(response);
                    callback(confResponse.Success);
                }, url, "GET", null, cookies, null);
            }, op);
        }

        public void GenerateConfirmationURL(Callback callback, string tag = "conf")
        {
            GenerateConfirmationQueryParams(queryString =>
            {
                callback(GenerateConfirmationURL(queryString));
            }, tag);
        }

        public string GenerateConfirmationURL(string queryString)
        {
            return APIEndpoints.COMMUNITY_BASE + "/mobileconf/conf?" + queryString;
        }

        public void GenerateConfirmationQueryParams(Callback callback, string tag)
        {
            if (String.IsNullOrEmpty(DeviceID))
                throw new ArgumentException("Device ID is not present");

            TimeAligner.GetSteamTime(time =>
            {
                callback("p=" + this.DeviceID + "&a=" + this.Session.SteamID.ToString() + "&k=" + _generateConfirmationHashForTime(time, tag) + "&t=" + time + "&m=android&tag=" + tag);
            });
        }

        private string _generateConfirmationHashForTime(long time, string tag)
        {
            int n2 = tag != null ? Math.Min(40, 8 + tag.Length) : 8;
            byte[] array = new byte[n2];
            for (int n4 = 7; n4 >= 0; n4--)
            {
                array[n4] = (byte)time;
                time >>= 8;
            }
            if (tag != null)
            {
                Array.Copy(Encoding.UTF8.GetBytes(tag), 0, array, 8, n2 - 8);
            }

            try
            {
                IBuffer identitySecretArray = CryptographicBuffer.DecodeFromBase64String(this.IdentitySecret);

                MacAlgorithmProvider hmacsha1 = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
                CryptographicKey hmacKey = hmacsha1.CreateKey(identitySecretArray);

                string encodedData = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Sign(hmacKey, CryptographicBuffer.CreateFromByteArray(array)));
                string hash = WebUtility.UrlEncode(encodedData);
                return hash;
            }
            catch (Exception)
            {
                return null; //Fix soon: catch-all is BAD!
            }
        }

        private delegate void ConfirmationCallback(ConfirmationDetailsResponse time);

        public void GetConfirmationTradeOfferID(LongCallback callback, Confirmation conf)
        {
            _getConfirmationDetails(confDetails =>
            {
                if (confDetails == null || !confDetails.Success)
                {
                    callback(-1);
                    return;
                }

                Regex tradeOfferIDRegex = new Regex("<div class=\"tradeoffer\" id=\"tradeofferid_(\\d+)\" >");
                if (!tradeOfferIDRegex.IsMatch(confDetails.HTML))
                {
                    callback(-1);
                    return;
                }
                callback(long.Parse(tradeOfferIDRegex.Match(confDetails.HTML).Groups[1].Value));
            }, conf);
        }

        private void _getConfirmationDetails(ConfirmationCallback callback, Confirmation conf)
        {
            string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/details/" + conf.ID + "?";
            GenerateConfirmationQueryParams(queryString =>
            {
                url += queryString;

                CookieContainer cookies = new CookieContainer();
                this.Session.AddCookies(cookies);
                GenerateConfirmationURL(referer =>
                {
                    SteamWeb.Request(response =>
                    {
                        if (String.IsNullOrEmpty(response))
                        {
                            callback(null);
                            return;
                        }

                        var confResponse = JsonConvert.DeserializeObject<ConfirmationDetailsResponse>(response);
                        callback(confResponse);
                    }, url, "GET", null, cookies, null);
                });
            }, "details");
        }

        //TODO: Determine how to detect an invalid session.
        public class WGTokenInvalidException : Exception
        {
        }

        private class RefreshSessionDataResponse
        {
            [JsonProperty("response")]
            public RefreshSessionDataInternalResponse Response { get; set; }
            internal class RefreshSessionDataInternalResponse
            {
                [JsonProperty("token")]
                public string Token { get; set; }

                [JsonProperty("token_secure")]
                public string TokenSecure { get; set; }
            }
        }

        private class RemoveAuthenticatorResponse
        {
            [JsonProperty("response")]
            public RemoveAuthenticatorInternalResponse Response { get; set; }

            internal class RemoveAuthenticatorInternalResponse
            {
                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class SendConfirmationResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }

        private class ConfirmationDetailsResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("html")]
            public string HTML { get; set; }
        }
    }
}