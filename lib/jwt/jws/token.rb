# frozen_string_literal: true

require 'jwt/error'

module JWT
  module JWS
    class Token
      SEGMENTS_LENGTH = 3
      ADJUSTMENT = 1
      SEPARATOR = '.'

      class << self
        def create(jws:)
          if valid?(jws: jws) == false
            raise JWT::FormatError.new("JWS should contains #{SEGMENTS_LENGTH} segments.")
          end

          header, payload, signature = jws.split(SEPARATOR)

          new(header: header, payload: payload, signature: signature)
        end

        def valid?(jws:)
          segments = jws.count(SEPARATOR) + ADJUSTMENT

          jws.kind_of?(String) && segments == SEGMENTS_LENGTH
        end
      end

      attr_reader :header, :payload, :signature, :segments

      def initialize(header:, payload:, signature:)
        @header = header
        @payload = payload
        @signature = signature

        @segments = [
          header, payload, signature
        ]
      end

      def decode!
        if header.empty? || payload.empty?
          raise JWT::FormatError.new("JWS should contains #{SEGMENTS_LENGTH} segments.")
        end

        @header = parse(JWT::Base64.url_decode(header))
        @payload = parse(JWT::Base64.url_decode(payload))

        if signature && signature.empty? == false
          @signature = JWT::Base64.url_decode(signature)
          @segments = segments.compact
        end
      end

      private

      def parse(segment)
        begin
          JWT::JSON.parse(segment)
        rescue ::JSON::ParserError
          raise JWT::DecodeError, 'Invalid segment encoding'
        end
      end
    end
  end
end