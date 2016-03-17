﻿using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace SteamAuth
{

    /// <summary>
    /// Handles the linking process for a new mobile authenticator.
    /// </summary>
    public class AuthenticatorLinker
    {
       

        /// <summary>
        /// Set to register a new phone number when linking. If a phone number is not set on the account, this must be set. If a phone number is set on the account, this must be null.
        /// </summary>
        public string PhoneNumber = null;

        /// <summary>
        /// Randomly-generated device ID. Should only be generated once per linker.
        /// </summary>
        public string DeviceID { get; private set; }

        /// <summary>
        /// After the initial link step, if successful, this will be the SteamGuard data for the account. PLEASE save this somewhere after generating it; it's vital data.
        /// </summary>
        public SteamGuardAccount LinkedAccount { get; set; }

        /// <summary>
        /// True if the authenticator has been fully finalized.
        /// </summary>
        public bool Finalized = false;

        private SessionData _session;
        private CookieContainer _cookies;

        public AuthenticatorLinker(SessionData session)
        {
            this._session = session;
            this.DeviceID = GenerateDeviceID();

            this._cookies = new CookieContainer();
            session.AddCookies(_cookies);
        }

        public void AddAuthenticator(LinkCallback callback)
        {
            _hasPhoneAttached(hasPhone =>
            {
                if (hasPhone && PhoneNumber != null)
                {
                    callback(LinkResult.MustRemovePhoneNumber);
                    return;
                }
                if (!hasPhone && PhoneNumber == null) {
                    callback(LinkResult.MustProvidePhoneNumber);
                    return;
                }

                BCallback numberAddedCallback = numberAdded =>
                {
                    if (!numberAdded)
                    {
                        callback(LinkResult.GeneralFailure);
                        return;
                    }

                    var postData = new Dictionary<string, string>();
                    postData["access_token"] = _session.OAuthToken;
                    postData["steamid"] = _session.SteamID.ToString();
                    postData["authenticator_type"] = "1";
                    postData["device_identifier"] = this.DeviceID;
                    postData["sms_phone_id"] = "1";

                    SteamWeb.MobileLoginRequest(response =>
                    {
                        if (response == null)
                        {
                            callback(LinkResult.GeneralFailure);
                            return;
                        }

                        var addAuthenticatorResponse = JsonConvert.DeserializeObject<AddAuthenticatorResponse>(response);
                        if (addAuthenticatorResponse == null || addAuthenticatorResponse.Response == null)
                        {
                            callback(LinkResult.GeneralFailure);
                            return;
                        }

                        if (addAuthenticatorResponse.Response.Status == 29)
                        {
                            callback(LinkResult.AuthenticatorPresent);
                            return;
                        }

                        if (addAuthenticatorResponse.Response.Status != 1)
                        {
                            callback(LinkResult.GeneralFailure);
                            return;
                        }

                        this.LinkedAccount = addAuthenticatorResponse.Response;
                        LinkedAccount.Session = this._session;
                        LinkedAccount.DeviceID = this.DeviceID;

                        callback(LinkResult.AwaitingFinalization);
                    }, APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", postData);
                };

                if (!hasPhone)
                {
                    _addPhoneNumber(numberAddedCallback);
                } else
                {
                    numberAddedCallback(true);
                }
            });
        }

        public void FinalizeAddAuthenticator(FinalizeCallback callback, string smsCode)
        {
            var postData = new Dictionary<string, string>();
            postData["steamid"] = _session.SteamID.ToString();
            postData["access_token"] = _session.OAuthToken;
            postData["activation_code"] = smsCode;
            int tries = 0;

            Callback makeRequest = r => { };

            /*Callback getAuthCode = response =>
            {
                if (tries == 0)
                {
                    makeRequest("");
                }
                else
                {
                    LinkedAccount.GenerateSteamGuardCode(makeRequest);
                }
            };*/

            Callback reqCallback = response =>
            {
                if (tries++ > 30)
                {
                    callback(FinalizeResult.GeneralFailure);
                    return;
                }

                if (response == null)
                {
                    callback(FinalizeResult.GeneralFailure);
                    return;
                }

                var finalizeResponse = JsonConvert.DeserializeObject<FinalizeAuthenticatorResponse>(response);

                if (finalizeResponse == null || finalizeResponse.Response == null)
                {
                    callback(FinalizeResult.GeneralFailure);
                    return;
                }

                if (finalizeResponse.Response.Status == 89)
                {
                    callback(FinalizeResult.BadSMSCode);
                    return;
                }

                if (finalizeResponse.Response.Status == 88)
                {
                    if (tries >= 30)
                    {
                        callback(FinalizeResult.UnableToGenerateCorrectCodes);
                        return;
                    }
                }

                if (!finalizeResponse.Response.Success)
                {
                    callback(FinalizeResult.GeneralFailure);
                    return;
                }

                if (finalizeResponse.Response.WantMore)
                {
                    tries++;
                    LinkedAccount.GenerateSteamGuardCode(makeRequest);
                    return;
                }

                this.LinkedAccount.FullyEnrolled = true;
                callback(FinalizeResult.Success);
            };

            makeRequest = response => {
                postData["authenticator_code"] = response;
                TimeAligner.GetSteamTime(steamTime => {
                    postData["authenticator_time"] = steamTime.ToString();

                    SteamWeb.MobileLoginRequest(reqCallback, APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", postData);
                });
            };

            //The act of checking the SMS code is necessary for Steam to finalize adding the phone number to the account.
            //Of course, we only want to check it if we're adding a phone number in the first place...

            if (!String.IsNullOrEmpty(this.PhoneNumber))
            {
                this._checkSMSCode(b =>
                {
                    if (b)
                    {
                        LinkedAccount.GenerateSteamGuardCode(makeRequest);
                    }
                    else
                    {
                        callback(FinalizeResult.BadSMSCode);
                    }
                }, smsCode);
            }
            else
            {
                LinkedAccount.GenerateSteamGuardCode(makeRequest);
            }
        }

        private void _checkSMSCode(BCallback callback, string smsCode)
        {
            var postData = new Dictionary<string, string>();
            postData["op"] = "check_sms_code";
            postData["arg"] = smsCode;
            postData["sessionid"] = _session.SessionID;

            SteamWeb.Request(response => {
                if (response == null)
                {
                    callback(false);
                    return;
                }

                var addPhoneNumberResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
                callback(addPhoneNumberResponse.Success);
            }, APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, _cookies);
        }

        private void _addPhoneNumber(BCallback callback)
        {
            var postData = new Dictionary<string, string>();
            postData["op"] = "add_phone_number";
            postData["arg"] = PhoneNumber;
            postData["sessionid"] = _session.SessionID;

            SteamWeb.Request(response =>
            {
                if (response == null)
                {
                    callback(false);
                    return;
                }

                var addPhoneNumberResponse = JsonConvert.DeserializeObject<AddPhoneResponse>(response);
                callback(addPhoneNumberResponse.Success);
            }, APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, _cookies);
        }

        private void _hasPhoneAttached(BCallback callback)
        {
            var postData = new Dictionary<string, string>();
            postData["op"] = "has_phone";
            postData["arg"] = "null";
            postData["sessionid"] = _session.SessionID;

            SteamWeb.Request(response =>
            {
                if (response == null)
                {
                    callback(false);
                    return;
                }

                var hasPhoneResponse = JsonConvert.DeserializeObject<HasPhoneResponse>(response);
                callback(hasPhoneResponse.HasPhone);
            }, APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, _cookies);
        }

        public enum LinkResult
        {
            MustProvidePhoneNumber, //No phone number on the account
            MustRemovePhoneNumber, //A phone number is already on the account
            AwaitingFinalization, //Must provide an SMS code
            GeneralFailure, //General failure (really now!)
            AuthenticatorPresent
        }

        public enum FinalizeResult
        {
            BadSMSCode,
            UnableToGenerateCorrectCodes,
            Success,
            GeneralFailure
        }

        private class AddAuthenticatorResponse
        {
            [JsonProperty("response")]
            public SteamGuardAccount Response { get; set; }
        }

        private class FinalizeAuthenticatorResponse
        {
            [JsonProperty("response")]
            public FinalizeAuthenticatorInternalResponse Response { get; set; }

            internal class FinalizeAuthenticatorInternalResponse
            {
                [JsonProperty("status")]
                public int Status { get; set; }

                [JsonProperty("server_time")]
                public long ServerTime { get; set; }

                [JsonProperty("want_more")]
                public bool WantMore { get; set; }

                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class HasPhoneResponse
        {
            [JsonProperty("has_phone")]
            public bool HasPhone { get; set; }
        }

        private class AddPhoneResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }

        public static string GenerateDeviceID()
        {
            IBuffer random = CryptographicBuffer.GenerateRandom(32);
            string random32 = CryptographicBuffer.EncodeToHexString(random).Replace("-", "").Substring(0, 32).ToLower();

            return "android:" + SplitOnRatios(random32, new[] { 8, 4, 4, 4, 12 }, "-");
        }

        private static string SplitOnRatios(string str, int[] ratios, string intermediate)
        {
            string result = "";

            int pos = 0;
            for (int index = 0; index < ratios.Length; index++)
            {
                result += str.Substring(pos, ratios[index]);
                pos = ratios[index];

                if (index < ratios.Length - 1)
                    result += intermediate;
            }

            return result;
        }
    }
}
