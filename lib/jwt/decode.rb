# frozen_string_literal: true

require 'json'

require 'jwt/jws/token'
require 'jwt/signature'
require 'jwt/verify'

module JWT
  class Decode
  	extend Forwardable

  	def_delegators :token, :header, :payload, :signature, :segments, :decode!

  	attr_reader :token, :options, :verify

    def initialize(jwt, key, verify, options, &keyfinder)
      @token = JWS::Token.create(jws: jwt)

      @key = key
      @options = options
      @verify = verify
      @keyfinder = keyfinder
    end

    def decode_segments
      decode!
      verify!

      [payload, header]
    end

    private

    def verify!
      return unless verify

      verify_signature

      Verify.verify_claims(payload, @options)
    end

    def verify_signature
      @key = find_key(&@keyfinder) if @keyfinder
      @key = ::JWT::JWK::KeyFinder.new(jwks: @options[:jwks]).key_for(header['kid']) if @options[:jwks]

      raise(JWT::IncorrectAlgorithm, 'An algorithm must be specified') if allowed_algorithms.empty?
      raise(JWT::IncorrectAlgorithm, 'Expected a different algorithm') unless options_includes_algo_in_header?

      Signature.verify(header['alg'], @key, segments.first(2).join('.'), signature)
    end

    def options_includes_algo_in_header?
      allowed_algorithms.include? header['alg']
    end

    def allowed_algorithms
      return options[:algorithm].split if options.key?(:algorithm)
      return options[:algorithms] if options.key?(:algorithms)

      []
    end

    def find_key(&keyfinder)
      key = (keyfinder.arity == 2 ? yield(header, payload) : yield(header))

      raise JWT::DecodeError, 'No verification key available' unless key

      key
    end
  end
end
