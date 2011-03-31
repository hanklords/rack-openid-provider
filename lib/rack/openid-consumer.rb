require 'net/http'
require 'uri'
require 'rack'
require 'rack/openid-common'


module Rack
  class OpenIDConsumer
    class Response
      include OpenID::Response

      def initialize(res) @res = res end
      def params; @h ||= OpenID.kv_decode(@res.body) end
      def session_mac; session.mac(dh_server_public, enc_mac_key) end
    end
    
    class Request
      include OpenID::Request

      def self.associate(endpoint)
        req = Request.new
        req.mode = 'associate'
        req.assoc_type = 'HMAC-SHA1'
        req.session_type = 'DH-SHA1'
        req.dh_consumer_public = OpenID::Sessions['DH-SHA1'].pub_key

        http_res = Net::HTTP.post_form(URI(endpoint), req.to_hash)
        
        res = Response.new(http_res)
        p res.session_mac        
      end
      
      attr_reader :params
      def initialize; @params = {'ns' => OpenID::NS} end
      def to_hash
        h = {}
        @params.each {|k,v| h["openid.#{k}"] = v}
        h
      end
    end

    DEFAULT_OPTIONS = {}
    DEFAULT_MIDDLEWARES = []

    attr_reader :options
    def initialize(app, options = {})
      @options = DEFAULT_OPTIONS.merge(options)
      @middleware = DEFAULT_MIDDLEWARES.reverse.inject(app) {|a, m| m.new(a)}
    end

    def call(env)
      Request.associate(env)
    end
  end
end
