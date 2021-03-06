﻿using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.DingTalk
{
    public class DingTalkAuthenticationOptions : AuthenticationOptions
    {
        public const string AUTHENTICATION_TYPE = "DingTalk";

        public DingTalkAuthenticationOptions()
            : base(AUTHENTICATION_TYPE)
        {
            Caption = "钉钉";
            ReturnEndpointPath = "/signin-dingTalk";
            AuthenticationMode = AuthenticationMode.Passive;
            AuthenticateType = DingTalkAuthenticateType.QrConnect;
            Scope = new string[] { "snsapi_login" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public WebRequestHandler BackchannelHttpHandler { get; set; }

        public IDingTalkAuthenticationProvider Provider { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public IList<string> Scope { get; private set; }

        public string ReturnEndpointPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public DingTalkAuthenticateType AuthenticateType { get; set; }

        /// <summary>
        /// 微信网站应用AppId
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// 微信网站应用AppSecret
        /// </summary>
        public string AppSecret { get; set; }

    }

}
