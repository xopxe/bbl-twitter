# bbl-twitter

... is a Barebones Lua Twitter module (OAuth-enabled) with minimal dependencies.

It is intended for thin/embedded platforms like OpenWRT routers.

Here's an example program:

```lua
local bblt = require("bbl-twitter")
local config = {
  consumer_key = 'xxx',
  consumer_secret = 'xxx',
}
local c = bblt.client(config.consumer_key, config.consumer_secret)
-- The following function will prompt on the console to visit a URL and
-- enter a PIN for out-of-band authentication
c:out_of_band_cli()

c:update_status("Look ma, I just authenticated my Lua twitter app!")
print(string.format("Authorized by user '%s'. My secrets are token_key '%s' token_secret '%s'",
  c.screen_name, c.token_key, c.token_secret))
```


## Dependencies

* Lua (5.1 assumed)
* luasocket
* luasec
* shell w/ echo support (ie nearly any shell)
* an openssl executable binary.

### Packages
+ On OpenWRT, packages required are openssl-util, lua, luasocket, luasec
+ On Debian/Ubuntu, packages required are openssl, lua, liblua5.1-socket2 lua-sec
+ Other OSes will be similar. :)

## License

MIT Licensed as per the LICENSE file.

## Authors

Originally by Angus Gratton (@projectgus), improved and now maintained by @xopxe.

Significant contributions by:
* Matthijs Kooijman @matthijskooijman
* (Your Name Here!)

## Overview

To be able to use any twitter feature, you'll have to get a consumer key
and consumer secret at `https://dev.twitter.com` and pass to to the client
function.

### Access token

To actually make resource requests (e.g., post tweets), you need to have
an access token. You can get an access token in three ways:

1. Get a single access token from `https://dev.twitter.com`. This only
works if you need access just your own account, no others. See
`https://dev.twitter.com/pages/oauth_single_token` for details.

2. Use the out-of-band (PIN) OAuth flow. This means you present the user
with a Twitter url he should visit. After clicking the authorize button
at that url, the user is presented with a verifier (PIN code) that is
entered back into your application. You can then "trade" the verifier
for an access token using the OAuth API.

3. Use the full (callback) OAuth flow, which is intended for web
applications. You redirect the user to a Twitter url. After clicking the
authorize button at that url, the user is redirected back to your
webapplication with a verifier in the url. You can again "trade" the
verifier for an access token using the OAuth API.

If you obtain an access token using method 2. or 3., you can save it
into persistent (secure) storage for later use (so you don't have to run
the authorization steps again). The access token can be obtained from
the `c.token_key` and `c.token_secret` values and can later be
passed into the `client()` function to reuse it.

## Examples

### Tweet from a client (known access token)
This assumes you already have an access token, obtained by any method
described above.

```lua
local bblt = require("bbl-twitter")
local c = bblt.client(config.consumer_key, config.consumer_secret, config.token_key, config.token_secret)
c:update_status("Look ma, tweets from Lua!")
```

### Tweet w/ error handling

When a library call fails, it will return nil followed by an error message, so
the returns of the various functions can be handled using the `assert`
function. This example shows how to handle errors in client() and update_status(), but
it applies to all other functions as well.

```lua
local bblt = require("bbl-twitter")
local c = assert(bblt.client(config.consumer_key, config.consumer_secret, config.token_key, config.token_secret))
local r, e = c:update_status("Look ma, this tweet might not make it!")
if (not r) then
  if string.match(e, "duplicate") then
    print("Best guess is this tweet was rejected as a duplicate. Did you already tweet this?")
  else
    print("Error sending tweet: " .. e)
  end
end
```

### Authenticate Out-Of-Band to Twitter using the console
This example uses the `out_of_band_cli` function, which handles prompting
the user with the authorization url and prompting for the pin code.

```lua
local bblt = require("bbl-twitter")
local config = {
  consumer_key = 'xxx',
  consumer_secret = 'xxx',
}
local c = bblt.client(config.consumer_key, config.consumer_secret)
-- The following function will prompt on the console to visit a URL and
-- enter a PIN for out-of-band authentication
c:out_of_band_cli()
c:update_status("Look ma, I just authenticated my Lua twitter app!")
print(string.format("Authorized by user '%s'. My secrets are token_key '%s' token_secret '%s'",
  c.screen_name, c.token_key, c.token_secret))
```

### Authenticate Out-Of-Band to Twitter using other I/O
This example shows the details of doing out-of-band authorization
(you'll need to fill in the TODOs with your favorite I/O method to make
it work, of course).

```lua
local bblt = require("bbl-twitter")
local c = bblt.client(config.consumer_key, config.consumer_secret)
-- First get a request token and declare we need to do out-of-band
-- authorization
c:get_request_token('oob')
local url = c:get_authorize_url()
-- TODO: Show the url to the user
-- TODO: obtain pin from the user
local pin = ...
-- Now, trade the pin for an access token
c:get_access_token(pin)

c:update_status("Look ma, I just authenticated my Lua twitter app!")
print(string.format("Authorized by user '%s'. My secrets are token_key '%s' token_secret '%s'",
                    c.screen_name, c.token_key, c.token_secret))
```

### Authenticate using a callback
This example shows how to use this stuff in a webapplication using a
callback. Again, fill in the TODOs for your webapp.

In the first request, you do:

```lua
local bblt = require("bbl-twitter")
local c = bblt.client(config.consumer_key, config.consumer_secret)
-- First get a request token and declare our callback url
c:get_request_token('http://www.example.org/mywebapp')
-- TODO: Store c.req_token and c.req_secret somewhere
local url = c:get_authorize_url()
-- TODO: Redirect user to url
```

After authorization is complete, the user will be redirected to
`http://www.example.org/mywebapp?oauth_token=...&oauth_verifier=...`

This request should be handled as follows:

```lua
local bblt = require("bbl-twitter")
local c = bblt.client(config.consumer_key, config.consumer_secret)

-- TODO: get oauth_verifier from the url
local verifier = ...
-- TODO: get oauth_token from the url
c.req_token = ...
-- TODO: compare req_token with stored req_token
-- TODO: get stored req_secret
c.req_secret = ...

-- Now, trade the verifier for an access token
c:get_access_token(verifier)

c:update_status("Look ma, I just authenticated my Lua twitter app!")
print(string.format("Authorized by user '%s'. My secrets are token_key '%s' token_secret '%s'",
                    c.screen_name, c.token_key, c.token_secret))
```

### Perform custom signed requests
The `signed_request` function can be used to perform other requests to the
Twitter API that require authorization. This example shows how you would
implement posting a new tweet if the `update_status` function would not
exist.

This assumes you already have an access token, obtained by any method
described above.

```lua
local bblt = require("bbl-twitter")
local c = bblt.client(config.consumer_key, config.consumer_secret, config.token_key, config.token_secret)
c:signed_request("/1.1/statuses/update.json", {status = "Look ma, tweets from Lua!"}, "POST")
```

### Provide bbl-twitter options in a global 'twitter_config' table

```lua
local bblt = require("bbl-twitter")
bblt.twitter_config.openssl = "/opt/bin/openssl" -- if your openssl is not on the PATH
bblt.twitter_config.consumer_key = "myconsumerkey"
bblt.twitter_config.consumer_secret = "myconsumersecret"
bblt.twitter_config.token_key = "myaccesstoken"
bblt.twitter_config.token_secret = "myaccesssecret"
bblt.client():update_status("Look ma, global settings!")
```

## Alternatives

Jeffrey Friedl has actually coded a pure Lua Twitter module right down
to SHA1 & HMAC-SHA1 implementations, which is quite impressive (if a
bit absurd!) Although as-written it is tied to the Adobe Lightroom plugin
environment. http://regex.info/blog/lua/twitter

bbl-twitter was inspired by "shtter" shell twitter client for OpenWRT,
by "lostman" http://lostman-worlds-end.blogspot.com/2010/05/openwrt_22.html


## Todo

* Add more Twitter API features (parsing JSON/XML without additional dependencies is hard.)
