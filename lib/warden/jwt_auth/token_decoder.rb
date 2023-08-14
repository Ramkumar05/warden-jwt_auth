# frozen_string_literal: true

require 'jwt/error'

module Warden
  module JWTAuth
    # Decodes a JWT into a hash payload into a JWT token
    class TokenDecoder
      include JWTAuth::Import['decoding_secret', 'rotation_secret', 'algorithm']

      # Decodes the payload from a JWT as a hash
      #
      # @see JWT.decode for all the exceptions than can be raised when given
      # token is invalid
      #
      # @param token [String] a JWT
      # @return [Hash] payload decoded from the JWT
      def call(token)
        decode(token, account_secret(token))
      rescue JWT::VerificationError
        decode(token, rotation_secret)
      end

      private

      def decode(token, secret)
        JWT.decode(token,
                   secret,
                   true,
                   algorithm: algorithm,
                   verify_jti: true)[0]
      end

      private

      def account_secret(token)
        return "#{Account.current.auth_secret}#{decoding_secret}" if Account.current

        return "#{fetch_account_key(token)}#{decoding_secret}"
        # return decoding_secret if Account.current.nil?
      end

      def fetch_account_key(token)
        _payload = JWT.decode(token, nil, verify=false)
        account_id = _payload.map { |hash| hash['account_id'] }.first
        return Account.find(account_id).auth_secret
      rescue Exception => e
        Rails.logger.error("Account data missing from JWT token. #{e.message} - #{token.inspect}")
        return nil
      end
    end
  end
end
