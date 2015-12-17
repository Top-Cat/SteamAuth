﻿using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SteamAuth
{

    /// <summary>
    /// Handles logging the user into the mobile Steam website. Necessary to generate OAuth token and session cookies.
    /// </summary>
    public class UserLogin
    {
        public string Username;
        public string Password;
        public ulong SteamID;

        public bool RequiresCaptcha;
        public string CaptchaGID = null;
        public string CaptchaText = null;

        public bool RequiresEmail;
        public string EmailDomain = null;
        public string EmailCode = null;

        public bool Requires2FA;
        public string TwoFactorCode = null;

        public SessionData Session = null;
        public bool LoggedIn = false;

        private CookieContainer _cookies = new CookieContainer();

        public UserLogin(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

        public void DoLogin(LoginCallback callback)
        {
            var postData = new Dictionary<string, string>();
            var cookies = _cookies;

            Callback hasCookies = res =>
            {
                postData.Add("username", this.Username);
                SteamWeb.MobileLoginRequest(rsaRawResponse =>
                {
                    if (rsaRawResponse == null || rsaRawResponse.Contains("<BODY>\nAn error occurred while processing your request."))
                    {
                        callback(LoginResult.GeneralFailure);
                        return;
                    }

                    var rsaResponse = JsonConvert.DeserializeObject<RSAResponse>(rsaRawResponse);

                    if (!rsaResponse.Success)
                    {
                        callback(LoginResult.BadRSA);
                        return;
                    }

                    BigInteger mod = new BigInteger(rsaResponse.Modulus, 16);
                    BigInteger exp = new BigInteger(rsaResponse.Exponent, 16);
                    var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                    RsaKeyParameters rsaParams = new RsaKeyParameters(false, mod, exp);

                    encryptEngine.Init(true, rsaParams);

                    byte[] passwordArr = Encoding.UTF8.GetBytes(this.Password);
                    string encryptedPassword = Convert.ToBase64String(encryptEngine.ProcessBlock(passwordArr, 0, passwordArr.Length));

                    postData.Clear();
                    postData.Add("username", this.Username);
                    postData.Add("password", encryptedPassword);

                    postData.Add("twofactorcode", this.TwoFactorCode ?? "");

                    postData.Add("captchagid", this.RequiresCaptcha ? this.CaptchaGID : "-1");
                    postData.Add("captcha_text", this.RequiresCaptcha ? this.CaptchaText : "");

                    postData.Add("emailsteamid", (this.Requires2FA || this.RequiresEmail) ? this.SteamID.ToString() : "");
                    postData.Add("emailauth", this.RequiresEmail ? this.EmailCode : "");

                    postData.Add("rsatimestamp", rsaResponse.Timestamp);
                    postData.Add("remember_login", "false");
                    postData.Add("oauth_client_id", "DE45CD61");
                    postData.Add("oauth_scope", "read_profile write_profile read_client write_client");
                    postData.Add("loginfriendlyname", "#login_emailauth_friendlyname_mobile");
                    postData.Add("donotcache", Util.GetSystemUnixTime().ToString());

                    SteamWeb.MobileLoginRequest(rawLoginResponse =>
                    {
                        var loginResponse = JsonConvert.DeserializeObject<LoginResponse>(rawLoginResponse);

                        if (loginResponse == null)
                        {
                            callback(LoginResult.GeneralFailure);
                            return;
                        }

                        if (loginResponse.Message != null && loginResponse.Message.Contains("Incorrect login"))
                        {
                            callback(LoginResult.BadCredentials);
                            return;
                        }

                        if (loginResponse.CaptchaNeeded)
                        {
                            this.RequiresCaptcha = true;
                            this.CaptchaGID = loginResponse.CaptchaGID;
                            callback(LoginResult.NeedCaptcha);
                            return;
                        }

                        if (loginResponse.EmailAuthNeeded)
                        {
                            this.RequiresEmail = true;
                            this.SteamID = loginResponse.EmailSteamID;
                            callback(LoginResult.NeedEmail);
                            return;
                        }

                        if (loginResponse.TwoFactorNeeded && !loginResponse.Success)
                        {
                            this.Requires2FA = true;
                            callback(LoginResult.Need2FA);
                            return;
                        }

                        if (loginResponse.Message != null && loginResponse.Message.Contains("too many login failures"))
                        {
                            callback(LoginResult.TooManyFailedLogins);
                            return;
                        }

                        if (loginResponse.OAuthData == null || loginResponse.OAuthData.OAuthToken == null || loginResponse.OAuthData.OAuthToken.Length == 0)
                        {
                            callback(LoginResult.GeneralFailure);
                            return;
                        }

                        if (!loginResponse.LoginComplete)
                        {
                            callback(LoginResult.BadCredentials);
                            return;
                        }
                        else
                        {
                            var readableCookies = cookies.GetCookies(new Uri("https://steamcommunity.com"));
                            var oAuthData = loginResponse.OAuthData;

                            SessionData session = new SessionData();
                            session.OAuthToken = oAuthData.OAuthToken;
                            session.SteamID = oAuthData.SteamID;
                            session.SteamLogin = session.SteamID + "%7C%7C" + oAuthData.SteamLogin;
                            session.SteamLoginSecure = session.SteamID + "%7C%7C" + oAuthData.SteamLoginSecure;
                            session.WebCookie = oAuthData.Webcookie;
                            session.SessionID = readableCookies["sessionid"].Value;
                            this.Session = session;
                            this.LoggedIn = true;
                            callback(LoginResult.LoginOkay);
                            return;
                        }
                    }, APIEndpoints.COMMUNITY_BASE + "/login/dologin", "POST", postData, cookies);
                }, APIEndpoints.COMMUNITY_BASE + "/login/getrsakey", "POST", postData, cookies);
            };

            if (cookies.Count == 0)
            {
                //Generate a SessionID
                string url = "https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client";
                cookies.Add(SteamWeb.uri, new Cookie("mobileClientVersion", "0 (2.1.3)", "/"));
                cookies.Add(SteamWeb.uri, new Cookie("mobileClient", "android", "/"));
                cookies.Add(SteamWeb.uri, new Cookie("Steam_Language", "english", "/"));

                WebHeaderCollection headers = new WebHeaderCollection();
                headers["X-Requested-With"] = "com.valvesoftware.android.steam.community";

                SteamWeb.MobileLoginRequest(hasCookies, url, "GET", null, cookies, headers);
            } else
            {
                hasCookies("");
            }
        }

        private class LoginResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("login_complete")]
            public bool LoginComplete { get; set; }

            [JsonProperty("oauth")]
            public string OAuthDataString { get; set; }

            public OAuth OAuthData
            {
                get
                {
                    return OAuthDataString != null ? JsonConvert.DeserializeObject<OAuth>(OAuthDataString) : null;
                }
            }

            [JsonProperty("captcha_needed")]
            public bool CaptchaNeeded { get; set; }

            [JsonProperty("captcha_gid")]
            public string CaptchaGID { get; set; }

            [JsonProperty("emailsteamid")]
            public ulong EmailSteamID { get; set; }

            [JsonProperty("emailauth_needed")]
            public bool EmailAuthNeeded { get; set; }

            [JsonProperty("requires_twofactor")]
            public bool TwoFactorNeeded { get; set; }

            [JsonProperty("message")]
            public string Message { get; set; }

            internal class OAuth
            {
                [JsonProperty("steamid")]
                public ulong SteamID { get; set; }

                [JsonProperty("oauth_token")]
                public string OAuthToken { get; set; }
                
                [JsonProperty("wgtoken")]
                public string SteamLogin { get; set; }

                [JsonProperty("wgtoken_secure")]
                public string SteamLoginSecure { get; set; }

                [JsonProperty("webcookie")]
                public string Webcookie { get; set; }
            }
        }

        private class RSAResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("publickey_exp")]
            public string Exponent { get; set; }

            [JsonProperty("publickey_mod")]
            public string Modulus { get; set; }

            [JsonProperty("timestamp")]
            public string Timestamp { get; set; }

            [JsonProperty("steamid")]
            public ulong SteamID { get; set; }
        }
    }

    public enum LoginResult
    {
        LoginOkay,
        GeneralFailure,
        BadRSA,
        BadCredentials,
        NeedCaptcha,
        Need2FA,
        NeedEmail,
        TooManyFailedLogins,
    }
}
