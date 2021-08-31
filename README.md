# Crystal JWT Mapping

Crystal JSON Serialization support for [jwt](https://github.com/crystal-community/jwt).

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     jwt_mapping:
       github: danny8376/jwt_mapping
   ```

2. Run `shards install`

## Usage

```crystal
require "jwt_mapping"

class Data
  # Enable jwt serialization
  # Also include JSON::Serializable
  # Defines following properties :
  # exp : Time
  # nbf : Time
  # iat : Time
  # aud : String | Array
  # iss : String
  # sub : String
  # jti : String
  # With human readable aliases :
  # expiration, not_before, issued_at, audience, issuer, subject, jwt_id
  # See https://github.com/crystal-community/jwt#supported-reserved-claim-names
  include JWT::Token

  # just define yout properities as normal JSON::Serializable
  property foo : String

  def initialize(@foo)
  end
end

data = Data.new("bar")
data.iat = Time.utc # set iat time

# The following is similar to original jwt

# Encode to jwt token
token = data.to_jwt("SecretKey", JWT::Algorithm::HS256)
# => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MzAyNDU2NDUsImZvbyI6ImJhciJ9.w14YgdhXBXl1L-dp8b6tF2Awtx6ufwa8aCykXW4UBdM"

# Decode from jwt token
payload, header = Data.from_jwt(token, "SecretKey", JWT::Algorithm::HS256)
# payload => #<Data:0x7fdb1dfede60 @exp=nil, @nbf=nil, @iss=nil, @aud=nil, @jti=nil, @iat=2021-08-29 14:00:45.0 UTC, @sub=nil, @foo="bar", @json_unmapped={}>
# header => {"typ" => "JWT", "alg" => "HS256"}

# You can optionally ignore verification and validation if you want to inspect the token
payload, header = iJWT.decode(token, verify: false, validate: false)
# Verification checks the signature
# Validation is checking if the token has expired etc

# You may also dynamically decide the key by passing a block to the decode function
# algorithm is optionally, you can omit it to use algorithm defined in the header
payload, header = Data.from_jwt(token, JWT::Algorithm::HS256) do |header, payload|
  "SecretKey"
end
```

## Test

```
crystal spec
```

## Contributing

1. Fork it (<https://github.com/danny8376/jwt_mapping/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [DannyAAM](https://github.com/danny8376) - creator and maintainer
