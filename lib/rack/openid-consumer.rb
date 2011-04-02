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
      def mac_key
        session.crypted? ? session.mac(dh_server_public, enc_mac_key) : @params["mac_key"]
      end
    end
    
    class Request
      include OpenID::Request
      
      attr_reader :params
      def initialize; @params = {'ns' => OpenID::NS} end
      
      def associate!(op_endpoint, params = {})
        @params.merge! params
        self.mode = "associate"
        @op_endpoint = op_endpoint
        direct!
      end
      
      def checkid_setup!(op_endpoint, params = {})
        @params.merge! params
        self.mode = "checkid_setup"
        @op_endpoint = op_endpoint
        finish!
      end
      
      def checkid_immediate!(op_endpoint, params = {})
        @params.merge! params
        self.mode = "checkid_immediate"
        @op_endpoint = op_endpoint
        finish!
      end
      
      def check_authentication(op_endpoint, params = {})
        @params.merge! params
        self.mode = "check_authentication"
        @op_endpoint = op_endpoint
        direct!
      end
      
      def http_headers
        headers = {"Content-Type" => "text/plain"}
        d = URI(@op_endpoint)
        d.query = d.query ? d.query + "&" + OpenID.url_encode(@params) : OpenID.url_encode(@params)
        headers.merge!("Location" => d.to_s)
      end
      
      def finish!; [302, http_headers, []] end
      alias :to_a :finish!
      
      def direct!
        h = Hash[@params.map {|k,v| ["openid.#{k}", v]}]
        http_res = Net::HTTP.post_form(URI(@op_endpoint), h)
        Response.new(http_res, true)        
      end
    end

    DEFAULT_OPTIONS = {}
    DEFAULT_MIDDLEWARES = []

    attr_reader :options
    def initialize(app, options = {})
      @options = DEFAULT_OPTIONS.merge(options)
      @associations, @handles = {}, {}
      @middleware = DEFAULT_MIDDLEWARES.reverse.inject(app) {|a, m| m.new(a)}
    end

    def call(env)
      c,h,b = @middleware.call(env)
      if c == 401 and auth_header = h["WWW-Authenticate"] and auth_header =~ /^OpenID /
        params = OpenIDConsumer.parse_header(auth_header)
        params["discovery"] = OpenID::Services.new(params["identity"])
        params["assoc_handle"] = get_associate_handle(env, params)
        checkid(env, params)
      else
        [c,h,b]
      end
    end
    
    private
    def get_associate_handle(env, params)
      op_endpoint = params["discovery"].default_op_endpoint
      if @associations[op_endpoint].nil?
        params["assoc_type"], params["session_type"] = "HMAC-SHA256", "DH-SHA256"
        res = associate(env, params)
        if assoc_handle = res.assoc_handle
          @handles[assoc_handle] = res.mac_key
          @associations[op_endpoint] = assoc_handle
        end
      end
      
      @associations[op_endpoint]
    end
    
    def associate(env, params)
      op_endpoint = params["discovery"].default_op_endpoint
      req = Request.new
      req.assoc_type = "HMAC-SHA256"
      req.session_type = "DH-SHA256"
      req.dh_consumer_public = OpenID::Sessions["DH-SHA256"].pub_key
      req.associate!(op_endpoint)
    end
    
    def checkid(env, params)
      identity, immediate = params["identity"], params["immediate"]
      discovery, assoc_handle = params["discovery"], params["assoc_handle"]

      if op_endpoint = discovery.default_op_endpoint
        req = Request.new
        req.assoc_handle = assoc_handle if assoc_handle
        req.claimed_id = discovery.default_claimed_id
        req.identity = discovery.default_identity
        req.realm = self_return_to(env)
        req.return_to = self_return_to(env)
        if immediate
          req.checkid_immediate!(op_endpoint)
        else
          req.checkid_setup!(op_endpoint)
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
