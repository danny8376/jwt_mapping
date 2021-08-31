require "jwt"

# TODO: Write documentation for `JwtMapping`
module JWT
  MAPPING_VERSION = "0.1.0"

  module Token
    macro included
      include JSON::Serializable

      {%
        props = [
          {
            name: "exp",
            longname: "expiration",
            type: Time?,
            converter: Time::EpochConverter
          },
          {
            name: "nbf",
            longname: "not_before",
            type: Time?,
            converter: Time::EpochConverter
          },
          {
            name: "iat",
            longname: "issued_at",
            type: Time?,
            converter: Time::EpochConverter
          },
          {
            name: "aud",
            longname: "audience",
            type: "String | Array(String) | Nil",
          },
          {
            name: "iss",
            longname: "issuer",
            type: String?,
          },
          {
            name: "sub",
            longname: "subject",
            type: String?,
          },
          {
            name: "jti",
            longname: "jwt_id",
            type: String?,
          }
        ]
      %}

      {% for prop in props %}
        {% if converter = prop[:converter] %}
          @[JSON::Field(converter: {{converter}})]
        {% end %}
        property {{prop[:name].id}} : {{prop[:type].id}}

        def {{prop[:longname].id}}
          @{{prop[:name].id}}
        end

        def {{prop[:longname].id}}=(value)
          @{{prop[:name].id}} = value
        end
      {% end %}

      # dummy for support of JSON::Serializable::Unmapped
			@[JSON::Field(ignore: true)]
      property json_unmapped = Hash(String, JSON::Any).new

      def to_jwt(key : String, algorithm : JWT::Algorithm, **header_keys) : String
        JWT.encode(self, key, algorithm, **header_keys)
      end

      def self.from_jwt(token : String, key : String = "", algorithm : JWT::Algorithm = JWT::Algorithm::None, verify = true, validate = true, **options) : Tuple
        JWT.decode_with_mapping(token, self, key, algorithm, verify, validate, **options)
      end

      def self.from_jwt(token : String, algorithm : JWT::Algorithm? = nil, verify = true, validate = true, **options, &block) : Tuple
        JWT.decode_with_mapping(token, self, algorithm, verify, validate, **options) do |header, payload|
          yield header, payload
        end
      end

      # dirty hack for compatibility with existing validation by emulating JSON::Any


      def [](key)
        case key
        {% for prop in props %}
          when "{{prop[:name].id}}"
          {% if prop[:type] == "String | Array(String) | Nil" %}
            if {{prop[:name].id}}.is_a? Array
              JSON::Any.new {{prop[:name].id}}.as(Array).map { |v| JSON::Any.new v }
            else
              JSON::Any.new {{prop[:name].id}}.as(String)
            end
          {% elsif prop[:type] == Time? %}
            JSON::Any.new {{prop[:name].id}}.not_nil!.to_unix
          {% elsif prop[:type] == String? %}
            JSON::Any.new {{prop[:name].id}}.not_nil!
          {% end %}
        {% end %}
        else
          json_unmapped[key]
        end
      end

      def []?(key)
        case key
        {% for prop in props %}
          when "{{prop[:name].id}}"
          {% if prop[:type] == "String | Array(String) | Nil" %}
            case {{prop[:name].id}}
            when Array
              JSON::Any.new {{prop[:name].id}}.as(Array).map { |v| JSON::Any.new v }
            when String
              JSON::Any.new {{prop[:name].id}}.as(String)
            else
              nil
            end
          {% elsif prop[:type] == Time? %}
            unless {{prop[:name].id}}.nil?
              JSON::Any.new {{prop[:name].id}}.not_nil!.to_unix
            end
          {% elsif prop[:type] == String? %}
            unless {{prop[:name].id}}.nil?
              JSON::Any.new {{prop[:name].id}}
            end
          {% end %}
        {% end %}
        else
          json_unmapped[key]?
        end
      end

      def as_h
        self
      end

      def as_h?
        self
      end
    end
  end

  class Payload
    include Token
    include JSON::Serializable::Unmapped

    def initialize
    end
  end

  def decode_with_mapping(token : String, payload_class = Payload, key : String = "", algorithm : Algorithm = Algorithm::None, verify = true, validate = true, **options) : Tuple
    verify_data, _, encoded_signature = token.rpartition('.')

    check_verify_data(verify_data)

    verify(key, algorithm, verify_data, encoded_signature) if verify

    header, payload = decode_verify_data(verify_data, payload_class)
    validate(payload, options) if validate

    {payload, header}
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT payload", error)
  end

  def decode_with_mapping(token : String, payload_class = Payload, algorithm : Algorithm? = nil, verify = true, validate = true, **options, &block) : Tuple
    verify_data, _, encoded_signature = token.rpartition('.')

    check_verify_data(verify_data)
    header, payload = decode_verify_data(verify_data, payload_class)

    if algorithm.nil?
      begin
        algorithm = Algorithm.parse header["alg"].as_s
      rescue error : ArgumentError | KeyError
        raise DecodeError.new("Invalid alg in JWT header", error)
      end
    end
    key = yield header, payload

    verify(key.not_nil!, algorithm.not_nil!, verify_data, encoded_signature) if verify
    validate(payload, options) if validate

    {payload, header}
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT payload", error)
  end


  private def decode_verify_data(verify_data, payload_class)
    encoded_header, encoded_payload = verify_data.split('.')
    header_json = Base64.decode_string(encoded_header)
    #header = header_class.from_json header_json
    header = JSON.parse(header_json).as_h

    payload_json = Base64.decode_string(encoded_payload)
    payload = payload_class.from_json payload_json

    { header, payload }
  rescue error : Base64::Error
    raise DecodeError.new("Invalid Base64", error)
  rescue error : JSON::SerializableError
    raise DecodeError.new("Invalid JSON", error)
  rescue error : TypeCastError
    raise DecodeError.new("Invalid JWT header", error)
  end
end
