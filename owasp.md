## Introduction  ##

###The .NET Framework###
The .NET Framework is Microsoft's principal platform for enterprise development. It is the supporting API for ASP.NET, Windows Desktop applications, Windows Communication Foundation services, SharePoint, Visual Studio Tools for Office and other technologies.

###Updating the Framework###
The .NET Framework is kept up-to-date by Microsoft with the Windows Update service. Developers do not normally need to run seperate updates to the Framework. Windows update can be accessed at [http://windowsupdate.microsoft.com/ Windows Update] or from the Windows Update program on a Windows computer.

Individual frameworks can be kept up to date using [http://nuget.codeplex.com/wikipage?title#Getting%20Started&referringTitle#Home NuGet]. As Visual Studio prompts for updates, build it into your lifecycle.

Remember that third party libraries have to be updated separately and not all of them use Nuget. ELMAH for instance, requires a separate update effort.

##.NET Framework Guidance##

The .NET Framework is the set of APIs that support an advanced type system, data, graphics, network, file handling and most of the rest of what is needed to write enterprise apps in the Microsoft ecosystem. It is a nearly ubiquitous library that is strong named and versioned at the assembly level.

### Data Access ###

* Use [http://msdn.microsoft.com/en-us/library/ms175528(v#sql.105).aspx Parameterized SQL] commands for all data access, without exception.
* Do not use [http://msdn.microsoft.com/en-us/library/system.data.sqlclient.sqlcommand.aspx SqlCommand] with a string parameter made up of a [http://msdn.microsoft.com/en-us/library/ms182310.aspx concatenated SQL String].
* Whitelist allowable values coming from the user. Use enums, [http://msdn.microsoft.com/en-us/library/f02979c7.aspx TryParse] or lookup values to assure that the data coming from the user is as expected.
** Enums are still vulnerable to unexpected values because .NET only validates a successful cast to the underlying data type, integer by default. [https://msdn.microsoft.com/en-us/library/system.enum.isdefined Enum.IsDefined] can validate whether the input value is valid within the list of defined constants.
* Apply the principle of least privilege when setting up the Database User in your database of choice. The database user should only be able to access items that make sense for the use case.
* Use of the [http://msdn.microsoft.com/en-us/data/ef.aspx Entity Framework] is a very effective [http://msdn.microsoft.com/en-us/library/ms161953(v#sql.105).aspx SQL injection] prevention mechanism. Remember that building your own ''ad hoc'' queries in EF is just as susceptible to SQLi as a plain SQL query.
* When using SQL Server, prefer integrated authentication over SQL authentication.

### Encryption ###
* Never, ever write your own encryption.
* Use the [http://msdn.microsoft.com/en-us/library/ms995355.aspx Windows Data Protection API (DPAPI)] for secure local storage of sensitive data.
* The standard .NET framework libraries only offer unauthenticated encryption implementations.  Authenticated encryption modes such as AES-GCM based on the underlying newer, more modern Cryptography API: Next Generation are available via the [https://clrsecurity.codeplex.com/ CLRSecurity library].
* Use a strong hash algorithm. 
** In .NET 4.5 the strongest algorithm for password hashing is PBKDF2, implemented as [http://msdn.microsoft.com/en-us/library/system.security.cryptography.rfc2898derivebytes(v#vs.110).aspx System.Security.Cryptography.Rfc2898DeriveBytes].
** In .NET 4.5 the strongest hashing algorithm for general hashing requirements is [http://msdn.microsoft.com/en-us/library/system.security.cryptography.sha512.aspx System.Security.Cryptography.SHA512].
** When using a hashing function to hash non-unique inputs such as passwords, use a salt value added to the original value before hashing.
* Make sure your application or protocol can easily support a future change of cryptographic algorithms.
* Use Nuget to keep all of your packages up to date. Watch the updates on your development setup, and plan updates to your applications accordingly.

### General ###

* Always check the MD5 hashes of the .NET Framework assemblies to prevent the possibility of rootkits in the framework. Altered assemblies are possible and simple to produce. Checking the MD5 hashes will prevent using altered assemblies on a server or client machine. See [[File:Presentation - .NET Framework Rootkits - Backdoors Inside Your Framework.ppt]]
* Lock down the config file. 
** Remove all aspects of configuration that are not in use. 
** Encrypt sensitive parts of the web.config using aspnet_regiis -pe

##ASP.NET Web Forms Guidance##

ASP.NET Web Forms is the original browser-based application development API for the .NET framework, and is still the most common enterprise platform for web application development.

* Always use [http://support.microsoft.com/kb/324069 HTTPS].
* Enable [http://msdn.microsoft.com/en-us/library/system.web.configuration.httpcookiessection.requiressl.aspx requireSSL] on cookies and form elements and [http://msdn.microsoft.com/en-us/library/system.web.configuration.httpcookiessection.httponlycookies.aspx HttpOnly] on cookies in the web.config.
* Implement [http://msdn.microsoft.com/en-us/library/h0hfz6fc(v#VS.71).aspx customErrors].
* Make sure [http://www.iis.net/configreference/system.webserver/tracing tracing] is turned off.
* While viewstate isn't always appropriate for web development, using it can provide CSRF mitigation. To make the ViewState protect against CSRF attacks you need to set the [http://msdn.microsoft.com/en-us/library/ms972969.aspx#securitybarriers_topic2 ViewStateUserKey]:

```java
 protected override OnInit(EventArgs e) {
     base.OnInit(e); 
     ViewStateUserKey # Session.SessionID;
 } 
```
If you don't use Viewstate, then look to the default master page of the ASP.NET Web Forms default template for a manual anti-CSRF token using a double-submit cookie.
```java
 private const string AntiXsrfTokenKey # "__AntiXsrfToken";
 private const string AntiXsrfUserNameKey # "__AntiXsrfUserName";
 private string _antiXsrfTokenValue;
 protected void Page_Init(object sender, EventArgs e)
 {
     // The code below helps to protect against XSRF attacks
     var requestCookie # Request.Cookies[AntiXsrfTokenKey];
     Guid requestCookieGuidValue;
     if (requestCookie !# null && Guid.TryParse(requestCookie.Value, out requestCookieGuidValue))
     {
        // Use the Anti-XSRF token from the cookie
        _antiXsrfTokenValue # requestCookie.Value;
        Page.ViewStateUserKey # _antiXsrfTokenValue;
     }
     else
     {
        // Generate a new Anti-XSRF token and save to the cookie
        _antiXsrfTokenValue # Guid.NewGuid().ToString("N");
        Page.ViewStateUserKey # _antiXsrfTokenValue;
        var responseCookie # new HttpCookie(AntiXsrfTokenKey)
        {
           HttpOnly # true,
           Value # _antiXsrfTokenValue
        };
        if (FormsAuthentication.RequireSSL && Request.IsSecureConnection)
        {
           responseCookie.Secure # true;
        }
        Response.Cookies.Set(responseCookie);
     }
     Page.PreLoad +# master_Page_PreLoad;
 }
 
 protected void master_Page_PreLoad(object sender, EventArgs e)
 {
     if (!IsPostBack)
     {
        // Set Anti-XSRF token
        ViewState[AntiXsrfTokenKey] # Page.ViewStateUserKey;
        ViewState[AntiXsrfUserNameKey] # Context.User.Identity.Name ?? String.Empty;
     }
     else
     {
        // Validate the Anti-XSRF token
        if ((string)ViewState[AntiXsrfTokenKey] !# _antiXsrfTokenValue || 
           (string)ViewState[AntiXsrfUserNameKey] !# (Context.User.Identity.Name ?? String.Empty))
        {
           throw new InvalidOperationException("Validation of Anti-XSRF token failed.");
        }
     }
 }
```
* Consider [http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security HSTS] in IIS.
** In the Connections pane, go to the site, application, or directory for which you want to set a custom HTTP header.
** In the Home pane, double-click HTTP Response Headers.
** In the HTTP Response Headers pane, click Add... in the Actions pane.
** In the Add Custom HTTP Response Header dialog box, set the name and value for your custom header, and then click OK.
* Remove the version header.

    <httpRuntime enableVersionHeader#"false" /> 

* Also remove the Server header.

    HttpContext.Current.Response.Headers.Remove("Server");

### HTTP validation and encoding ###

* Do not disable [http://www.asp.net/whitepapers/request-validation validateRequest] in the web.config or the page setup. This value enables the XSS protection in ASP.NET and should be left intact as it provides partial prevention of Cross Site Scripting.
* The 4.5 version of the .NET Frameworks includes the AntiXssEncoder library, which has a comprehensive input encoding library for the prevention of XSS. Use it.
* Whitelist allowable values anytime user input is accepted. The regex namespace is particularly useful for checking to make sure an email address or URI is as expected.
* Validate the URI format using [http://msdn.microsoft.com/en-us/library/system.uri.iswellformeduristring.aspx Uri.IsWellFormedUriString].

### Forms authentication ###

* Use cookies for persistence when possible. Cookieless Auth will default to UseDeviceProfile.
* Don't trust the URI of the request for persistence of the session or authorization. It can be easily faked.
* Reduce the forms authentication timeout from the default of 20 minutes to the shortest period appropriate for your application. If slidingExpiration is used this timeout resets after each request, so active users won't be affected.
* If HTTPS is not used, slidingExpiration should be disabled.  Consider disabling slidingExpiration even with HTTPS. 
* Always implement proper access controls.
** Compare user provided username with User.Identity.Name.
** Check roles against User.Identity.IsInRole.
* Use the ASP.NET Membership provider and role provider, but review the password storage. The default storage hashes the password with a single iteration of SHA-1 which is rather weak. The ASP.NET MVC4 template uses [http://www.asp.net/identity/overview/getting-started/introduction-to-aspnet-identity ASP.NET Identity] instead of ASP.NET Membership, and ASP.NET Identity uses PBKDF2 by default which is better. Review the OWASP [[Password Storage Cheat Sheet]] for more information.
* Explicitly authorize resource requests.
* Leverage role based authorization using User.Identity.IsInRole.

##ASP.NET MVC Guidance##

ASP.NET MVC (Model-View-Controller) is a contemporary web application framework that uses more standardized HTTP communication than the Web Forms postback model.

* Always use HTTPS.
* Use the Synchronizer token pattern. In Web Forms, this is handled by ViewState, but in MVC you need to use ValidateAntiForgeryToken.
* Remove the version header.

    MvcHandler.DisableMvcResponseHeader # true;

* Also remove the Server header.

    HttpContext.Current.Response.Headers.Remove("Server");

* Decorate controller methods using PrincipalPermission to prevent unrestricted URL access.
* Make use of IsLocalUrl() in logon methods.
```java
    if (MembershipService.ValidateUser(model.UserName, model.Password)) 
    { 
        FormsService.SignIn(model.UserName, model.RememberMe); 
        if (IsLocalUrl(returnUrl)) 
        { 
            return Redirect(returnUrl); 
        } 
        else 
        { 
            return RedirectToAction("Index", "Home"); 
        } 
    } 
```
* Use the [http://msdn.microsoft.com/en-us/library/dd492767(v#vs.108).aspx AntiForgeryToken] on every form post to prevent CSRF attacks. In the HTML:
```java
    <% using(Html.Form(“Form", "Update")) { %>
        <%# Html.AntiForgeryToken() %>
    <% } %>
```
and on the controller method:

```java
    [ValidateAntiForgeryToken]
    public ViewResult Update()
    {
        // gimmee da codez
    }
 ```
* Maintain security testing and analysis on Web API services. They are hidden inside MEV sites, and are public parts of a site that will be found by an attacker. All of the MVC guidance and much of the WCF guidance applies to the Web API.

##XAML Guidance##

* Work within the constraints of Internet Zone security for your application.
* Use ClickOnce deployment. For enhanced permissions, use permission elevation at runtime or trusted application deployment at install time.


##Windows Forms Guidance## 

* Use partial trust when possible. Partially trusted Windows applications reduce the attack surface of an application. Manage a list of what permissions your app must use, and what it may use, and then make the request for those permissions declaratively at run time.
* Use ClickOnce deployment. For enhanced permissions, use permission elevation at runtime or trusted application deployment at install time.

##WCF Guidance##

* Keep in mind that the only safe way to pass a request in RESTful services is via HTTP POST, with TLS enabled. GETs are visible in the querystring, and a lack of TLS means the body can be intercepted.
* Avoid BasicHttpBinding. It has no default security configuration. Use WSHttpBinding instead.
* Use at least two security modes for your binding. Message security includes security provisions in the headers. Transport security means use of SSL. TransportWithMessageCredential combines the two.
* Test your WCF implementation with a fuzzer like the Zed Attack Proxy.

## Authors and Primary Editors  ##

* Bill Sempf - bill.sempf(at)owasp.org
* Troy Hunt - troyhunt(at)hotmail.com
* Jeremy Long - jeremy.long(at)owasp.org
