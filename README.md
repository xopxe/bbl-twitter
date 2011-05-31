# bbl-twitter

... is a Barebones Lua Twitter module (OAuth-enabled) with minimal dependencies.

It is intended for thin/embedded platforms like OpenWRT routers.

## Dependencies

* Lua (5.1 assumed)
* luasocket
* shell w/ echo support (ie nearly any shell)
* an openssl executable binary.

### Packages
+ On OpenWRT, packages required are openssl-util, lua, luasocket
+ On Debian/Ubuntu, packages required are openssl, lua, liblua5.1-socket2
+ Other OSes will be similar. :)

## License

MIT Licensed as per the LICENSE file.


## Examples

### Tweet from a client (known preset consumer & request secrets)
(If it's your app then you can authenticate yourself for a developer/hardcoded request secret via http://dev.twitter.com)

```lua
require("bbl-twitter")
c=client(config.consumer_key, config.consumer_secret, config.request_token, config.request_secret)
update_status(c, "Look ma, tweets from Lua!")
```

### Tweet w/ error handling
```lua
require("bbl-twitter")
c=client(config.consumer_key, config.consumer_secret, config.request_token, config.request_secret)
local r, e = update_status(c, "Look ma, this tweet might not make it!")
if (not r) then
  if string.match(e, "duplicate") then
    print("Best guess is this tweet was rejected as a duplicate. Did you already tweet this?")
  else
    print("Error sending tweet: " .. e)
  end
end
```

### Authenticate Out-Of-Band to Twitter
```lua
require("bbl-twitter")
c=client(config.consumer_key, config.consumer_secret)
-- The following function will prompt on the console to visit a URL and
-- enter a PIN for out-of-band authentication
out_of_band_cli(c)
update_status(c, "Look ma, I just authenticated my Lua twitter app!")
print(string.format("My secrets are request_token '%s' request_secret '%s'",
								c.token_key, c.token_secret))
```

### Provide bbl-twitter options in a global 'twitter_config' table
```lua
require("bbl-twitter")
twitter_config.openssl = "/opt/bin/openssl" -- if your openssl is not on the PATH
twitter_config.consumer_key = "myconsumerkey"
twitter_config.consumer_secret = "myconsumersecret"
twitter_config.token_key = "myrequesttoken"
twitter_config.token_secret = "myrequestsecret"
update_status(client(), "Look ma, global settings!")
```

## Alternatives

Jeffrey Friedl has actually coded a pure Lua Twitter module right down
to SHA1 & HMAC-SHA1 implementations, which is quite impressive (if a
bit absurd!) Although as-written it is tied to the Adobe Lightroom plugin
environment. http://regex.info/blog/lua/twitter

bbl-twitter was inspired by "shtter" shell twitter client for OpenWRT,
by "lostman" http://lostman-worlds-end.blogspot.com/2010/05/openwrt_22.html
(lostman's is better if you want command-line tweeting on a very
severe budget!)

If you have easy access to luarocks + working C compiler then a better
fully-featured option may be ltwitter - https://github.com/TheLinx/ltwitter

## Todo

* Make less bodgy
* Add more Twitter API features (parsing JSON/XML w/o additional dependencies FTL)
