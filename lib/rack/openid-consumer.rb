require 'net/http'
require 'uri'
require 'rack'
require 'rack/openid-common'


module Rack
  class OpenIDConsumer
    class Response
      include OpenID::Response

      attr_reader :params
      def initialize(res, direct = false)
        @params = if direct
          OpenID.kv_decode(res.body)
        else
          OpenID.extract_open_id_params(Rack::Request.new(res).params)
        end
      end
      
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
        
        res = Response.new(http_res, true)
        p res.session_mac        
      end
      
      attr_reader :params
      def initialize; @params = {'ns' => OpenID::NS} end
      def to_hash
        h = {}
        @params.each {|k,v| h["openid.#{k}"] = v}
        h
      end
      
      def checkid_setup!(op_endpoint)
        mode = "checkid_setup"
        @op_endpoint = op_endpoint
        finish!
      end
      
      def checkid_immediate!(op_endpoint)
        mode = "checkid_immediate"
        @op_endpoint = op_endpoint
        finish!
      end
      
      def http_headers
        headers = {"Content-Type" => "text/plain"}
        d = URI(@op_endpoint)
        d.query = d.query ? d.query + "&" + OpenID.url_encode(@params) : OpenID.url_encode(@params)
        headers.merge!("Location" => d.to_s)
      end
      
      def finish!; [302, http_headers, []] end
      alias :to_a :finish!
    end

    DEFAULT_OPTIONS = {}
    DEFAULT_MIDDLEWARES = []

    attr_reader :options
    def initialize(app, options = {})
      @options = DEFAULT_OPTIONS.merge(options)
      @middleware = DEFAULT_MIDDLEWARES.reverse.inject(app) {|a, m| m.new(a)}
    end

    def call(env)
      @middleware.call(env)
    end
  end
end
