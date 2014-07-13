-- bbl-twitter "Barebones Lua Twitter"
--
-- Copyright (c) 2011 Angus Gratton, released under the MIT License
-- (see the included file LICENSE.)
--
-- See the README.md file for details or visit http://github.com/projectgus/bbl-twitter
--

-- adapted by xxopxe@gmail.com
--   * table as module.
--   * twitter api 1.1
--		  * some url changed
--		  * moved to https (added dependency on luasec)

local http = require("socket.http")
local https = require("ssl.https")

local M = {}

-------------------
-- Util functions
-------------------

-- Taken from http://lua-users.org/wiki/StringRecipes then modified for RFC3986
local function url_encode(str)
	if (str) then
		str = string.gsub(str, "([^%w-._~])", function (c)
			return string.format ("%%%02X", string.byte(c))
		end)
	end
	return str
end


--  taken from http://lua-users.org/wiki/SortedIteration

local function __genOrderedIndex( t )
	local orderedIndex = {}
	for key in pairs(t) do
		table.insert( orderedIndex, key )
	end
	table.sort( orderedIndex )
	return orderedIndex
end

local function orderedNext(t, state)
	-- Equivalent of the next function, but returns the keys in the alphabetic
	-- order. We use a temporary ordered key table that is stored in the
	-- table being iterated.
	
	local key
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

local function orderedPairs(t)
	-- Equivalent of the pairs() function on tables. Allows to iterate
	-- in order
	return orderedNext, t, nil
end

-------------------
-- End Util functions
-------------------

local function cmd_output(cmd)
	local f = assert(io.popen(cmd, 'r'))
	local res = assert(f:read('*a'))
	f:close()
	return res
end

-- Configuration elements for twitter client
M.twitter_config = {
	openssl = "openssl",
	url = "https://api.twitter.com",
}

local function join_http_args(args)
	local first = true
	local res = ""

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
	local cmd = string.format(
		"echo -n \"%s\" | %s sha1 -hmac \"%s&%s\" -binary | %s base64",
		query, M.twitter_config.openssl,
		client.consumer_secret, client.token_secret or "",
		M.twitter_config.openssl
	)
	local hash = cmd_output(cmd)
	hash = string.gsub(hash, "\n", "")
	return join_http_args(args) .. "&oauth_signature=" .. url_encode(hash)
end


local function https_get(client, url, args)
	local argdata = sign_http_args(client, "GET", url, args)
 	if not string.find(url, "?") then
		url = url .. "?"
	end
	local b, c = https.request(url .. argdata)
	if b and (c ~= 200) then
		return nil, "Error " .. c .. ": " .. b
	else
		return b, c
	end
end

local function https_post(client, url, postargs)
	local b, c = https.request(url, sign_http_args(client, "POST", url, postargs))								
	if b and (c ~= 200) then
		return nil, "Error " .. c .. ": " .. b
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

local function get_base_args(client, args)
	args = args or {}

	args.oauth_consumer_key=client.consumer_key
	args.oauth_nonce=generate_nonce()
	args.oauth_signature_method="HMAC-SHA1"
	args.oauth_timestamp=os.time()
	args.oauth_token=client.token_key
	args.oauth_version="1.0"

	return args
end

-- Get a request token and secret
--
-- callback is the url passed to Twitter where the user is
-- redirected back to after authorizing. If this is not a webapp and/or you
-- need to use out-of-band authorization, pass "oob" as the callback
-- (the user will then be presented a pincode that should be entered
-- back into the application).
--
-- Token is stored in client.req_token and client.req_secret.
function M.get_request_token(client, callback)
	local args = get_base_args(client)
	args.oauth_callback = callback
	local r, e = https_get( client, M.twitter_config.url .. "/oauth/request_token", args)
  if not r then return nil, "Could not get OAuth request token: " .. tostring(e) end
	
	client.req_token = string.match(r, "oauth_token=([^&]*)")
	client.req_secret = string.match(r, "oauth_token_secret=([^&]*)")

	return client
end

-- Get the url the user should navigate to to authorize the request
-- token.
function M.get_authorize_url(client)
	if not (client.req_token and client.req_secret) then
	return nil,  "Cannot authorize request token when there is none"
  end
	-- The user should visit this url to authorize the token
	return M.twitter_config.url .. "/oauth/authorize?" .. join_http_args({oauth_token = client.req_token})
end

function M.out_of_band_cli(client)
	-- Request a token
	M.get_request_token(client, 'oob')

	-- Get the url to authorize it
	local url = M.get_authorize_url(client)

	print("Open this URL in your browser and enter back the PIN")
	print(url)
	io.write("pin >")
	local req_pin = io.read("*line")

	M.get_access_token(client, req_pin)
end

-- Get an access token after obtaining user authorization for a request
-- token. The verifier is either the "oauth_verifier" parameter passed
-- to the callback, or the pin entered by the user.
--
-- To be able to use this function, you should make sure that both the
-- client.req_token and client.req_secret are present (and match the
-- request token the verifier is for).
--
-- The obtained access token is stored inside the client, which can be
-- used to make authenticated request afterwards. To preserve the
-- authentication for a longer period of time, store the
-- client.token_key and client.token_secret in persistent storage.
-- Also, after obtaining an access token, client.user_id and
-- client.screen_name contain the user_id (numerical) and screen_name
-- (username) of the authorizing user.
function M.get_access_token(client, verifier)
	if not (client.req_token and client.req_secret) then
		return nil, "Can't get access token without request token"
	end
	-- Sign the access_token request using the request token. Note that
	-- Twitter does not currently require this, it seems to ignore the
	-- signature on access_token requests alltogether (which is in
	-- violation with the OAuth spec and their own documentation). To
	-- prevent making this code a bad example and problems when Twitter
	-- ever becomes compliant, we'll do this the proper way.
	client.token_key = client.req_token
	client.token_secret = client.req_secret

	local args = {
		oauth_token=client.req_token,
		oauth_verifier=verifier
	}
	local s, r = M.signed_request(client, "/oauth/access_token", args, "GET")
	if not s then
		return nil, "Unable to get access token: " .. tostring(r)
	end

	client.token_key = string.match(r, "oauth_token=([^&]*)")
	client.token_secret = string.match(r, "oauth_token_secret=([^&]*)")
	client.screen_name = string.match(r, "screen_name=([^&]*)")
	client.user_id = string.match(r, "userid=([^&]*)")
	--print("key = " .. client.token_key)
	--print("secret = " .. client.token_secret)
	return client
end

--
-- Perform a signed (authenticated) request to the twitter API. If the
-- url starts with /, the Twitter API base url (twitter_config.url) is
-- automatically prepended.
--
-- method can be "GET" or "POST". When no method is specified, a POST
-- request is made.
--
-- Returns the response body when the request was succesful. Raises an
-- error when the request fails for whatever reason.
function M.signed_request(client, url, args, method)
	if not client.token_secret then
		return nil, "Cannot perform signed request without token_secret"
	end
  
	method = method or "POST"
	args = args or {}

	if (string.sub(url, 1, 1) == "/") then
		url = M.twitter_config.url .. url
	end

	args = get_base_args(client, args)
	local r, e
	if (method == "GET") then
		r, e = https_get(client, url, args)
	else
		r, e = https_post(client, url, args)
	end
	if not r then
		return nil, "Unable to perform signed request: " .. tostring(e)
	end
	return r
end

function M.update_status(client, tweet)
	return M.signed_request(client, "/1.1/statuses/update.json", {status = tweet})
end

function M.client(consumer_key, consumer_secret, token_key, token_secret, verifier)
	local client = {}
	for j,x in pairs(M.twitter_config) do client[j] = x end
	-- args can be set in twitter_config if you want them global
	client.consumer_key = consumer_key or client.consumer_key
	client.consumer_secret = consumer_secret or client.consumer_secret
	client.token_key = token_key or client.token_key
	client.token_secret = token_secret or client.token_secret

	if not (client.consumer_key and client.consumer_secret) then
		return nil, "you need to specify a consumer key and a consumer secret!"
	end
	
	setmetatable(client, {__index=M})
	return client
end

return M

-- vim: set ts=3 sts=3 sw=3 noexpandtab:
