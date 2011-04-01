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

      def self.associate(endpoint, params = {})
        req = Request.new
        req.mode = 'associate'
        req.assoc_type = 'HMAC-SHA1'
        req.session_type = 'DH-SHA1'
        req.dh_consumer_public = OpenID::Sessions['DH-SHA1'].pub_key
        req.params.merge!(params)
        
        http_res = Net::HTTP.post_form(URI(endpoint), req.to_hash)
        Response.new(http_res, true)
      end

      def self.check_authentication(endpoint, params = {})
        req = Request.new
        req.mode = 'check_authentication'
        req.params.merge!(params)

        http_res = Net::HTTP.post_form(URI(endpoint), req.to_hash)
        Response.new(http_res, true)
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
      c,h,b = @middleware.call(env)
      if c == 401 and auth_header = h["WWW-Authenticate"] and auth_header =~ /^OpenID /
        params = OpenIDConsumer.parse_header(auth_header)
        checkid(env, params)
      else
        [c,h,b]
      end
    end
    
    private
    def checkid(env, params)
      identity, immediate = params['identity'], params['immediate']
      discovery = OpenID::Services.new(identity)
      if service = discovery.service(OpenID::SERVER) and
          !service["URI"].empty?
        identity = OpenID::IDENTIFIER_SELECT
      elsif service = discovery.service(OpenID::SIGNON) and
          !service["URI"].empty?
        identity = discovery.claimed_id
      else
        identity = nil
      end
      
      if identity
        req = Request.new
        req.claimed_id = req.identity = identity
        req.realm = self_return_to(env)
        req.return_to = self_return_to(env)
        if immediate
          req.checkid_setup!(service["URI"].first)
        else
          req.checkid_immediate!(service["URI"].first)
        end
      else
        [302, {"Content-Length" => "0", "Location" => self_return_to(env)}, []]
      end
    end

    def self_return_to(env)
      Rack::Request.new(env.merge "PATH_INFO" => "/", "QUERY_STRING" => "").url
    end

    def self.build_header(params = {})
      "OpenID " + params.map { |k, v|
        v = [v] if !v.respond_to? :to_ary
        %{#{k}="#{v.join(',')}"}
      }.join(', ')
    end

    def self.parse_header(str)
      params = {}
      if header_match = str[/^OpenID\s+(.*)$/, 1]
        header_match.split(', ').each { |pair|
          kv_match = /^(\w+)="(.*)"$/.match(pair)
          k, v = kv_match[1..2]
          next if k.nil? or v.nil?
          params[k] = v =~ /,/ ? v.split(',') : v
        }
      end
      params
    end
  end

end
