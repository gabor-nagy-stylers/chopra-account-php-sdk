Server Requirements
===================

-   PHP &lt;= 5.4

-   PHP Memcache module

-   OpenSSL module

-   PECL Hash &lt;= 1.1 ([*http://php.net/manual/en/function.hash-hmac.php*](http://php.net/manual/en/function.hash-hmac.php))

-   PHP CURL module

Structure of the SDK
====================

Client.php: Client-side main class. This is the only class that needs to be instantiated on each run where a user session is required.

Api.php: It is responsible for the API connection and communication. No instantiation is required, it is done by Client.php.

Session.php: It is responsible for the management of the user session, no instantiation is required, it is done by Client.php.

It uses memcache connection for session management; so the php\_memcache module needs to be enabled on the server.

There is no autoloader in the SDK (yet), so all three files are needed to be put in “require” clause on each run, or to be loaded by a private auto-load solution.

Operational process
===================

Standard Integration Flow
---------------------
Flow chart of how to integrate this SDK into your system can be found [here](https://choprasso-public.s3.amazonaws.com/uploads/standard_integration_flow.png).

Instantiation
-------------

It is necessary to instantiate the Client class with the proper parameters on each run where a user session is required (in middleware or in the init, or during bootstrap):

```php
$client = new Client([
	'client_key' => '[your_client_key]',
	'client_secret' => '[your_32_chars_client_secret]',
	'session_host' => '[memcache_host_name]',
	'session_port' => '[memcache_port]',
	'endpoint_basepath' => 'http://account.chopra.com/', 
	'api_key' => '[api_secret_key]',
	'api_endpoint' => 'http://account-api.chopra.com/', 
    'cookie_domain' => '[cookie_domain]'
]);
```

#### Client Parameters
* __endpoint_basepath:__ only necessary in dev environment – the live domain is predefined into the SDK.
* __api_endpoint:__ api_endpoint is only necessary in dev environment – the live domain is predefined into the SDK.
* __cookie_domain:__ cookie domain is optional. if not provided, sdk generates it from $_SERVER request parameters. it must be the main domain of your system. if you use multiple subdomains for the same authentication system, than you should provide the main domain without subdomain. if your entire site is on a subdomain you have to provide the full domain with subdomain, eg. ayurveda.chopra.com

**!Notice:** Code above and session check below with redirection have to run ONLY when http request is initiated by a browser, or in other cases where it’s necessary. Do not include it when your system is requested by a cron job, or running in CLI.

Session check
-------------

Needs to be checked on each run: which user is stored in the SSO session.

This can be done as follows:

```php
try {
	// it throws an exception if there is no cookie or it is wrong or it has a invalid session ID
	$ssoUser = $client->getUser();
} catch (SSOAuthException $e) {
	// in this case you should redirect to SSO check URL which restore the user session from an existing session ID or if the user is not logged in (there is no existing session) then creates a guest session
	header('Location: ' . $client->getCheckUrl('http://[yourhost.tld]')); 
    // you have to provide the redirect URL as parameter where the SSO should redirect back to. It can be any URL where this code snippet runs again. You can redirect to any URL because this code should be executed at each runtime.
}
```

Redirect
--------

After redirection the response from SSO have to be checked and processed, like any other ouath / sso solution does. This is done by the getUser method automatically (mentioned in section 3.2 above). When the getUser method returns member type user, local user process can be done with it (store in local database, connect with existing local user, store in global scope for runtime, etc)

When returned user array is guest type, it means there is no logged in SSO user, and the returned array looks like this: \[ '\_auth\_type' =&gt; 'guest' \]

Initiating the SSO Login process
--------------------------------

After finishing the above process, the client class-object method memberLoggedIn() makes it possible to check whether it is a member type session or a guest type session, and then write out a link on the sso login page so that the user can start the process:

```php
if (!$client->memberLoggedIn()) {
	// we display an SSO login URL.

	// for the getLoginUrl params you have to give a redirect URL also
	echo '<a href="' . $client->getLoginUrl('http://[yourhost.tld]') . '">Login with SSO</a>';
}
```

Following the redirect to the SSO and a successful login or registration there, when returning to the page we get a full user array in $ssoUser, with all the data of the user. (The try-catch program branch, mentioned in section 3.2 above, needs to happen on each run so that the $ssoUser variable will be present all the time.)

**!Notice:** method memberLoggedIn can be called only after a successful session checking. If code in section 3.2. returns an SSOAuthException, then you have to do a redirect to check url as it is described above.

Logout
------

The getLogoutUrl() method of the client class returns a URL, and that is where the browser needs to be redirected. This method also expects a redirect\_url parameter.

```php
if ($client->memberLoggedIn()) {
	echo $client->getLogoutUrl('http://[yourhost.tld]');
}
```

Profile update on SSO page
--------------------------

The getProfileEditUrl() method of the client class returns a URL, and that is where the browser needs to be redirected. This method also expects a redirect\_url parameter to redirect the browser to after the profile modification is done.

```php
if ($client->memberLoggedIn()) {
	echo $client->getProfileEditUrl('http://[yourhost.tld]');
}
```    

Initiating the SSO Social Login process
---------------------------------------

### Local social authentication

As a first step, the locally linked social authentication needs to be performed. This can be either facebook or google.

### Redirection to the SSO Social login page

Next, the user needs to be redirected to the sso social login page, with the social data as parameters. The example below will not run, and neither will the code snippet found in example.php, because it requires the social ID and social Token acquired by the local social authentication.

```php
if (!$client->memberLoggedIn()) {
	echo '<a href="' . $client->getLoginUrl('http://[yourhost.tld]') . '">Login with SSO</a>';
	echo '<a href="' . $client->getSocialLoginUrl('http://[yourhost.tld]', 'google', ['id' => '{social_id}', 'token' => '{social_token}' ]) . '">Login with social</a>';
}
```

Parameters of getSocialLoginUrl:

1.  redirect_url, the SSO redirects here after the successful login

2.  social network type, options: google, facebook

3.  In php array: ['id' => '{social_id}', 'token' => '{social_token}' ] – obviously, social id and social token must be substituted with the proper values. These two values are required, can not be null or empty, otherwise SDK will raise an exception.

The processing workflow following the redirect is the same as in the case of a normal login.

After the local social auth you can redirect the user back to the return URL what you get back from getSocialLoginUrl method.

Create Sage User ID for SSO User
------------------------------------
By default User datas returned by getUser method contains the Sage User ID for the user. But if not, you can easily create a Sage User ID for an SSO user by a simple API call to SSO API endpoint. If user not exists in Sage system, it will be automatically created. 
You can do this with the SDK like this:
```php
        $postData = [
            'zip_code' => '1234', // any zip code, required by Sage system
            'user_id' => '342567' // SSO User ID
        ];

        $sageUser = $client->api()->makeCall(
            'mas_user_id',
            'POST',
            [],
            $postData
        );
```

