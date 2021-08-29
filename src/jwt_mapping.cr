require "jwt"

# TODO: Write documentation for `JwtMapping`
module JWT
  MAPPING_VERSION = "0.1.0"

  module AudConverter
    def self.from_json(pull : JSON::PullParser)
      case pull.kind
      when .string?
        pull.read_string
      when .begin_array?
        ary = [] of String
        pull.read_array do
          ary << pull.read_string
        end
        ary
      else
        raise DecodeError.new("Invalid claim aud")
      end
    end
    def self.to_json(values : Array(String) | String | Nil, builder : JSON::Builder)
      case values
      in Array(String)
        builder.array do
          values.each do |v|
            builder.string v
          end
        end
      in String
        builder.string values
      in Nil
        # do nothing
      end
    end
  end

  module Token
    macro included
      include JSON::Serializable

      @[JSON::Field(converter: Time::EpochConverter)]
      property exp : Time?
      @[JSON::Field(converter: Time::EpochConverter)]
      property nbf : Time?
      property iss : String?
      @[JSON::Field(converter: JWT::AudConverter)]
      property aud : Array(String) | String | Nil
      property jti : String?
      @[JSON::Field(converter: Time::EpochConverter)]
      property iat : Time?
      property sub : String?

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

      {% time_vars = ["exp", "nbf", "iat"] %}
      {% str_vars = ["iss", "jti", "sub"] %}

      def [](key)
        case key
        when "aud"
          if aud.is_a? Array
            JSON::Any.new aud.as(Array).map { |v| JSON::Any.new v }
          else
            JSON::Any.new aud.as(String)
          end
        {% for var in time_vars %}
          when "{{var.id}}"
            JSON::Any.new {{var.id}}.not_nil!.to_unix
        {% end %}
        {% for var in str_vars %}
          when "{{var.id}}"
            JSON::Any.new {{var.id}}.not_nil!
        {% end %}
        else
          json_unmapped[key]
        end
      end

      def []?(key)
        case key
        when "aud"
          case aud
          when Array
            JSON::Any.new aud.as(Array).map { |v| JSON::Any.new v }
          when String
            JSON::Any.new aud.as(String)
          else
            nil
          end
        {% for var in time_vars %}
          when "{{var.id}}"
            unless {{var.id}}.nil?
              JSON::Any.new {{var.id}}.not_nil!.to_unix
            end
        {% end %}
        {% for var in str_vars %}
          when "{{var.id}}"
            unless {{var.id}}.nil?
              JSON::Any.new {{var.id}}
            end
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
