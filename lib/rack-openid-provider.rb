require 'rack'
require 'openssl'
require 'time'
require 'uri'

module OpenID
  NS="http://specs.openid.net/auth/2.0".freeze
  class << self
    def btwoc(n)
      raise if n < 0
      r = (n % 0x100).chr
      r = (n % 0x100).chr + r while (n /= 0x100) > 0
      r = 0.chr + r if r[0].ord >= 0x80
      r
    end
    
    def ctwob(s)
      n, sl = 0, s.length - 1
      0.upto(sl) {|i|
        n += s[i].ord * 0x100 ** (sl - i)
      }
      n
    end

    def url_encode(h); h.map { |k,v| "#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}" }.join('&') end
    def kv_encode(h); h.map {|k,v| "openid." + k.to_s + ":" + v.to_s + 10.chr }.join end
    def kv_decode(s); Hash[*s.split(10.chr).map {|l| l.split(":", 2) }.flatten] end
    def base64_encode(s); [s].pack("m").rstrip end
    def base64_decode(s); s.unpack("m").first end
    def random_bytes(bytes); OpenSSL::Random.random_bytes(bytes).unpack("H*")[0] end

    def gen_sig(mac, params)
      signed = params['signed'].split(",").map {|k| [k, params[k]]}
      if mac.length == 20
        Signatures["HMAC-SHA1"].sign(  mac, kv_encode(signed))
      else
        Signatures["HMAC-SHA256"].sign(mac, kv_encode(signed))
      end
    end
  end

  module Signatures
    def self.[](name)
      @assocs ||= Hash[*constants.map {|c|
        a = const_get(c)
        [a.assoc, a] if a.respond_to? :assoc
      }.compact.flatten]
      @assocs[name]
    end

    class Assoc
      attr_reader :assoc
      def initialize(assoc, digest); @assoc, @digest = assoc.freeze, digest.new end
      def sign(mac, value); OpenSSL::HMAC.new(mac, @digest.reset).update(value) end
      def size; @digest.size end
      def gen_mac; OpenId.random_bytes(@digest.size) end
    end

    HMAC_SHA1 = Assoc.new "HMAC_SHA1", OpenSSL::Digest::SHA1
    HMAC_SHA256 = Assoc.new "HMAC_SHA256", OpenSSL::Digest::SHA256
  end

  module DH
    DEFAULT_MODULUS=0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
    DEFAULT_GEN=2

    class SHA_ANY
      class MissingKey < StandardError; end

      attr_reader :session_name
      def compatible_key_size?(size); @digest.size == size end
      def initialize(session_name, digest); @session_name, @digest = session_name.freeze, digest.new end

      def to_hash(mac, p, g, consumer_public_key)
        raise MissingKey if consumer_public_key.nil?
        p ||= DEFAULT_MODULUS
        g ||= DEFAULT_GEN
        private_key = random_bytes(@digest.size).to_i(16) % p
        public_key = g ** private_key % p
        shared = consumer_public_key ** private_key % p
        shared_hashed = @digest.reset.update(OpenID.btwoc(shared).digest)
        {
          "dh_server_public" => OpenID.base64_encode(OpenID.btwoc(public_key)),
          "enc_mac_key" => OpenID.base64_encode(sxor(shared_hashed, mac))
        }
      end

      private
      def sxor(s1, s2)
        # s1 = s1.to_enum(:each_byte); s2 = s2.to_enum(:each_byte)
        s1.bytes.zip(s2.bytes).map { |x,y| (x^y).chr }.join
      end
    end

    SHA1   = SHA_ANY.new "DH-SHA1"  , OpenSSL::Digest::SHA1
    SHA256 = SHA_ANY.new "DH-SHA256", OpenSSL::Digest::SHA256

    class NoEncryption
      def self.compatible_key_size?(size); true end
      def self.session_name; "no-encryption".freeze end
      def self.to_hash(mac, p, g, c); {"mac_key" => OpenID.base64_encode(mac)} end
    end

    def self.[](name)
      @sessions ||= Hash[*constants.each {|c|
        s = const_get(c)
        [s.session_name, s] if s.respond_to? :session_name
      }.compact.flatten]
      @sessions[name]
    end
  end
end


module Rack
  class OpenIdProvider
    module Utils
      include OpenID
      def redirect_positive(env, params = {}); redirect_res env, gen_pos(env, params) end
      def redirect_negative(env, params = {}); redirect_res env, gen_neg(env, params) end
      def redirect_error(env, error, params = {}); redirect_res env, gen_error(error, params) end
      def redirect_res(env, h)
        openid = env['openid.provider.req']
        d = URI(openid['return_to'])
        d.query = d.query ? d.query + "&" + OpenID.url_encode(h) : OpenID.url_encode(h)

        [301, {'Location' => d.to_s}, []]
      end

      def positive_htmlform(env, params= {}); gen_htmlform env, gen_pos(env, params) end
      def negative_htmlform(env, params= {}); gen_htmlform env, gen_neg(env, params) end
      def error_htmlform(env, error, params = {}); gen_htmlform env, gen_error(error, params) end
      def gen_htmlform(env, h)
        openid = env['openid.provider.req']
        d = Rack::Utils.escape(openid['return_to'])
        form = "<form name='openid_form' method='post' action='#{d}'>"
        h.each {|k,v| form << "<input type='hidden' name='#{Rack::Utils.escape k}' value='#{Rack::Utils.escape v}' />"}
        form << "<input type='submit' /></form>"
      end

      def gen_pos(env, params = {})
        openid = env['openid.provider.req']
        invalidate_handle = env['openid.provider.invalidate_handle']
        assoc_handle = env['openid.provider.assoc_handle']
        mac = env['openid.provider.mac']
        options = env['openid.provider.options']
        r = params.merge(
          "openid.ns" => NS,
          "openid.mode" => "id_res",
          "openid.op_endpoint" => options['op_endpoint'],
          "openid.return_to" => openid['return_to'],
          "openid.response_nonce" => gen_nonce,
          "openid.assoc_handle" => assoc_handle,
        )
        r["openid.invalidate_handle"] = invalidate_handle if invalidate_handle
        if not r["openid.signed"]
          r["openid.signed"] = "op_endpoint,return_to,assoc_handle,response_nonce"
          r["openid.signed"] << ",identity,claimed_id" if r["openid.identity"] and r["claimed_id"]
        end
        r["openid.sig"] = OpenID.gen_sig(mac, r)
        r
      end
  
      def gen_neg(env, params = {})
        openid = env['openid.provider.req']
        if openid['openid.mode'] == "checkid_immediate"
          params.merge "ns" => NS, "openid.mode" => "setup_needed"
        else
          params.merge "ns" => NS, "openid.mode" => "cancel"
        end
      end

      def gen_error(error, params = {})
        params.merge("ns" => NS, "openid.mode" => "error", "openid.error" => error)
      end

      def gen_nonce; Time.now.utc.iso8601 + OpenID.random_bytes(4) end
    end
    
    include Utils
    DEFAULT_OPTIONS = {
      'handle_timeout' => 36000,
      'checkid_immediate' => false,
      'pass_not_openid' => false
    }

    def initialize(app, options = {})
      @app = app
      @options = DEFAULT_OPTIONS.merge(options)
      @handles, @private_handles = {}, {}
    end

    def call(env)
      req = Request.new(env)
      openid = open_id_params(req.params)
      env['openid.provider.req'] = openid
      env['openid.provider.options'] = @options
      clean_handles

      case openid['mode']
      when 'associate'
        associate(env, openid)
      when 'checkid_immediate'
        if @options['checkid_immediate']
          checkid(env, openid)
          @app.call(env)
        else
          redirect_negative(env)
        end
      when 'checkid_setup'
        checkid(env, openid)
        @app.call(env)
      when 'check_authentication'
        check_authentication(env, openid)
      else
        if @options['pass_not_openid']
          @app.call(env)
        else
          [404, {"Content-Type" => "text/plain"}, ["Not Found: #{env["PATH_INFO"]}"]]
        end
      end
    end

    private
    def clean_handles; end
    
    def associate(env, openid)
      dh_modulus, dh_gen, dh_consumer_public = openid['dh_modulus'], openid['dh_gen'], openid['dh_consumer_public']
      p = dh_modulus && OpenID.ctwob(OpenID.base64_decode(dh_modulus))
      g = dh_gen && OpenIDctwob(OpenID.base64_decode(dh_gen))
      consumer_public_key = dh_consumer_public && OpenIDctwob(OpenIDbase64_decode(dh_consumer_public))

      session_type = OpenID::DH[openid['session_type']]
      assoc_type = OpenID::Signatures[openid['assoc_type']]

      if session_type.nil? or assoc_type.nil?
        return direct_error("session type or association type not supported", "error_code" => "unsupported-type")
      elsif not session_type.compatible_key_size?(assoc_type.size)
        return direct_error("session type and association type are incompatible")
      end
      
      mac = assoc_type.gen_mac
      handle = gen_handle
      r = {
        "assoc_handle" => handle,
        "session_type" => session_type,
        "assoc_type" => assoc_type,
        "expires_in" => @options['handle_timeout']
      }
      
      begin
        r.update session_type.to_hash(mac, p, g, consumer_public_key)
      rescue OpenID::DH::ANY_KEY::MissingKey
        return direct_error("dh_consumer_public missing")
      end
      
      @handle[handle] = mac
      direct_response r
    end

    def checkid(env, openid)
      assoc_handle = openid['assoc_handle']
      if mac = @handle[assoc_handle]
        env['openid.provider.assoc_handle'] = assoc_handle
        env['openid.provider.mac'] = mac
      else
        env['openid.provider.invalidate_handle'] = assoc_handle
        env['openid.provider.assoc_handle'] = phandle = gen_handle
        env['openid.provider.mac'] = @private_handles[phandle] = OpenID::Signatures["HMAC_SHA256"].gen_mac
      end
    end
    
    def check_authentication(env, openid)
      assoc_handle = openid['assoc_handle']
      invalidate_handle = openid['invalidate_handle']
      if mac = @private_handles[assoc_handle] and OpenID.gen_sig(mac, openid) == openid['sig']
        r = {"is_valid" => "true"}
        r["invalidate_handle"] = invalidate_handle if @handle[invalidate_handle].nil?
        direct_response  r
      else
        direct_response "is_valid" => "false"
      end
    end

    def open_id_params(params)
      openid_params = {}
      params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
      openid_params
    end
    
    def direct_response(params)
      [
        200,
        ["Content-Type" => "text/plain"],
        [OpenID.kv_encode(params.merge "ns" => NS)]
      ]
    end

    def direct_error(error, params = {})
      [
        400,
        ["Content-Type" => "text/plain"],
        [OpenID.kv_encode(params.merge "ns" => NS, "mode" => "error", "error" => error)]
      ]
    end
    
    def gen_handle; Time.now.utc.iso8601 + OpenID.random_bytes(4) end
  end
end
