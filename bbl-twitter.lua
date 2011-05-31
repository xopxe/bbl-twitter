-- bbl-twitter "Barebones Lua Twitter"
--
-- An OAuth-enabled Lua twitter client with _no dependencies_ 
-- apart from luasocket, openssl.
--
-- For very thin platforms like embedded systems
--
-- Requirements: luasocket, shell w/ echo support (ie most any shell) & openssl 
-- (on the path, or with path set at twitter_config.openssl property.)
--
-- Inspired by "shtter" shell twitter client for OpenWRT, by "lostman"
-- http://lostman-worlds-end.blogspot.com/2010/05/openwrt_22.html
-- (lostman's is better if you want command-line tweeting on a severe budget!)
--
-- If you have easy access to luarocks + working C compiler then a better option is
-- ltwitter - https://github.com/TheLinx/ltwitter
--
--
-- Example code
--
-- c=client(<My consumer key>, <My consumer secret>)
-- update_status(c, "My awesome new tweet!")
--
-- The client step in the example will prompt you to verify a PIN. 
-- If you don't want to authorise it interactively, supply request_token/request_secret
-- as additional params to client() or assign them to twitter_config
--
-- TODO: make less bodgy. :)

local http = require("socket.http")

-- Configuration elements for twitter client
twitter_config = {
	openssl = "openssl",
}

local function join_http_args(args)
	local first = true
	local res = ""
	local ampersand

	for a,v in orderedPairs(args or {}) do 
		if not first then
			res = res .. "&"
		end
		first = false
		res = res .. a .. "=" .. url_encode(v)
	end
	return res
end

local function sign_http_args(client, method, url, args)
	local query = string.format("%s&%s&%s", method, url_encode(url), url_encode(join_http_args(args)))		
	local cmd = string.format("echo -n \"%s\" | %s sha1 -hmac \"%s&%s\" -binary | %s base64", 
				 						 query, twitter_config.openssl, 
										 client.consumer_secret, client.token_secret or "",
										 twitter_config.openssl)
	local hash = cmd_output(cmd)
	hash = string.gsub(hash, "\n", "")
	return join_http_args(args) .. "&oauth_signature=" .. url_encode(hash)
end

function cmd_output(cmd)
	--print("Running " .. cmd)
	local f = assert(io.popen(cmd, 'r'))
	local res = assert(f:read('*a'))
	--print ("Got back " .. res)
	f:close()
	return res
end

local function http_get(client, url, args)
	local argdata = sign_http_args(client, "GET", url, args)
 	if not string.find(url, "?") then
		url = url .. "?" 
	end
	local b, c = http.request(url .. argdata)
	if b and (c ~= 200) then
		return nil, b .. ("Error " .. c)
	else
		return b, c
	end
end

local function http_post(client, url, postargs)
	local b, c = http.request(url, sign_http_args(client, "POST", url, postargs))								
	if b and (c ~= 200) then
		return nil, b .. ("Error " .. c)
	else
		return b, c
	end
end

local function generate_nonce()
	math.randomseed( os.time() )
	local src = ""
	for i=1,32 do
		src = src .. string.char(string.byte("a")+math.random(0,25))
	end
	return src
end

local function get_base_args(client)
	return { 	oauth_consumer_key=client.consumer_key,
					oauth_nonce=generate_nonce(),
					oauth_signature_method="HMAC-SHA1",
					oauth_timestamp=os.time(),
					oauth_token=client.token_key,
					oauth_version="1.0" 
				}
end

-- Interact w/ the user to get us an access token & secret for the client, if not supplied
local function get_access_token(client)
	r, e = http_get( client, "http://twitter.com/oauth/request_token", get_base_args(client))
	assert(r, "Could not get OAuth request token: " .. e)
	
	local req_token = string.match(r, "oauth_token=([^&]*)")
	local req_secret = string.match(r, "oauth_token_secret=([^&]*)")

	print("Open this URL in your browser and enter back the PIN")
	print("http://twitter.com/oauth/authorize?oauth_token=" .. req_token)
	io.write("pin >")
	local req_pin = io.read("*line")

	args = get_base_args(client)
	args.oauth_token=req_token
	args.oauth_verifier=req_pin
	r, e = http_get( client, "http://twitter.com/oauth/access_token", args)
	assert(r, "Unable to get access token: " .. e)

	client.token_key = string.match(r, "oauth_token=([^&]*)")
	client.token_secret = string.match(r, "oauth_token_secret=([^&]*)")
	--print("key = " .. client.token_key)
	--print("secret = " .. client.token_secret)
	return client
end

function update_status(client, tweet)
	local args = get_base_args(client)
	args.status = tweet
	return http_post(client, "http://api.twitter.com/1/statuses/update.xml", args)
end
							  

function client(consumer_key, consumer_secret, token_key, token_secret, verifier)
	local client = {}
	for j,x in pairs(twitter_config) do client[j] = x end
	-- args can be set in twitter_config if you want them global
	client.consumer_key = consumer_key or client.consumer_key 
	client.consumer_secret = consumer_secret or client.consumer_secret
	client.token_key = token_key or client.token_key
	client.token_secret = token_secret or client.token_secret

	assert(client.consumer_key and client.consumer_secret, "you need to specify a consumer key and a consumer secret!")
	if not (client.token_key and client.token_secret) then
		get_access_token(client)
	end
	return client
end


-------------------
-- Util functions
-------------------

-- Taken from http://lua-users.org/wiki/StringRecipes then modified for RFC3986
function url_encode(str)
  if (str) then
	  str = string.gsub(str, "([^%w-._~])",
								function (c) return string.format ("%%%02X", string.byte(c)) end)
  end
  return str	
end


--  taken from http://lua-users.org/wiki/SortedIteration
--[[
Ordered table iterator, allow to iterate on the natural order of the keys of a
table.

Example:
]]

function __genOrderedIndex( t )
    local orderedIndex = {}
    for key in pairs(t) do
        table.insert( orderedIndex, key )
    end
    table.sort( orderedIndex )
    return orderedIndex
end

function orderedNext(t, state)
    -- Equivalent of the next function, but returns the keys in the alphabetic
    -- order. We use a temporary ordered key table that is stored in the
    -- table being iterated.

    --print("orderedNext: state = "..tostring(state) )
    if state == nil then
        -- the first time, generate the index
        t.__orderedIndex = __genOrderedIndex( t )
        key = t.__orderedIndex[1]
        return key, t[key]
    end
    -- fetch the next value
    key = nil
    for i = 1,table.getn(t.__orderedIndex) do
        if t.__orderedIndex[i] == state then
            key = t.__orderedIndex[i+1]
        end
    end

    if key then
        return key, t[key]
    end

    -- no more value to return, cleanup
    t.__orderedIndex = nil
    return
end

function orderedPairs(t)
    -- Equivalent of the pairs() function on tables. Allows to iterate
    -- in order
    return orderedNext, t, nil
end
