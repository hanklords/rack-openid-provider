require 'rack'
require 'openssl'
require 'time'
require 'uri'

module Rack
  class OpenIdProvider
    module Utils
      NS="http://specs.openid.net/auth/2.0".freeze
      
      def redirect_positive(env, params = {}); redirect_res env, gen_pos(env, params) end
      def redirect_negative(env, params = {}); redirect_res env, gen_neg(env, params) end
      def redirect_error(env, error, params = {}); redirect_res env, gen_error(error, params) end
      def redirect_res(env, h)
        openid = env['openid.provider.req']
        d = URI(openid['return_to'])
        d.query = d.query ? d.query + "&" + url_encode(h) : url_encode(h)
              
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
        r["openid.sig"] = gen_sig(mac, r)
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
              
      def url_encode(h); h.map { |k,v| "#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}" }.join('&') end
      def kv_encode(h); h.map {|k,v| "openid." + k.to_s + ":" + v.to_s + 10.chr }.join end
#    def kv_decode(s); Hash[*s.split(10.chr).map {|l| l.split(":", 2) }.flatten] end
              
      def hmac_sha1(mac, value)
        OpenSSL::HMAC.new(mac, OpenSSL::Digest::SHA1.new).update(value)
      end
    
      def hmac_sha256(mac, value)
        OpenSSL::HMAC.new(mac, OpenSSL::Digest::SHA256.new).update(value)
      end
    
      def gen_random(bytes); OpenSSL::Random.random_bytes(bytes).unpack("H*")[0] end
      def gen_nonce; Time.now.utc.iso8601 + gen_random(4) end
        
      def gen_sig(mac, params)
        signed = params['signed'].split(",").map {|k| [k, params[k]]}
        if mac.length == 20
          hmac_sha1(  mac, kv_encode(signed))
        else
          hmac_sha256(mac, kv_encode(signed))
        end
      end
    end
    
    include Utils
    DEFAULT_OPTIONS = {}
    DH_MODULUS=0XDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
    DH_GEN=2

    def initialize(app, options = DEFAULT_OPTIONS)
      @app, @options = app, options
      @handles, @private_handles = {}, {}
    end

    def call(env)
      req = Request.new(env)
      openid = open_id_params(req.params)
      env['openid.provider.req'] = openid
      env['openid.provider.options'] = @options

      case openid['mode']
      when 'associate'
        associate(env, env['openid.provider.req'])
      when 'checkid_immediate', 'checkid_setup'
        clean_handles
        assoc_handle = openid['assoc_handle']
        if mac = @handle[assoc_handle]
          env['openid.provider.assoc_handle'] = assoc_handle
          env['openid.provider.mac'] = mac
        else
          env['openid.provider.invalidate_handle'] = assoc_handle
          env['openid.provider.assoc_handle'] = phandle = gen_handle
          env['openid.provider.mac'] = @private_handles[phandle] = gen_mac(32)
        end
        
        @app.call(env)
      when 'check_authentication'
        clean_handles
        check_authentication(env, env['openid.provider.req'])
      else
        @app.call(env)
      end
    end

    private
    def clean_handles; end
    
    def associate(env, openid)
      session_type, assoc_type = openid['session_type'], openid['assoc_type']
      dh_modulus, dh_gen, dh_consumer_public = openid['dh_modulus'], openid['dh_gen'], openid['dh_consumer_public']
      p = dh_modulus ? ctwob(base64_decode(dh_modulus)) : DH_MODULUS
      g = dh_gen ? ctwob(base64_decode(dh_gen)) : DH_GEN
      consumer_public_key = dh_consumer_public ? ctwob(base64_decode(dh_consumer_public)) : nil

      len = case assoc_type
      when "HMAC-SHA256"
        32 if session_type != "DH-SHA1"
      when "HMAC-SHA1"
        20 if session_type != "DH-SHA256"
      else
        false
      end
      return direct_error("session type and association type are incompatible", "error_code" => "unsupported-type") if not len
      
      mac = gen_mac(len)
      handle = gen_handle
      r = {
        "assoc_handle" => handle,
        "session_type" => session_type,
        "assoc_type" => assoc_type,
        "expires_in" => 36000
      }
      
      r.update case session_type
      when "DH-SHA256"
        dh_sha256(mac, p, g, consumer_public_key)
      when "DH-SHA1" 
        return direct_error("dh_consumer_public missing") if not consumer_public_key
        dh_sha1(mac, p, g, consumer_public_key)
      when "no-encryption" 
        no_encryption(mac)
      end
      
      @handle[handle] = mac
      direct_response r
    end
    
    def check_authentication(env, openid)
      assoc_handle = openid['assoc_handle']
      invalidate_handle = openid["invalidate_handle"]
      if mac = @private_handles[assoc_handle] and gen_sig(mac, openid) == openid['sig']
        r = {"is_valid" => "true"}
        r["invalidate_handle"] = invalidate_handle if @handle[invalidate_handle].nil?
        direct_response 
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
        [kv_encode(params.merge "ns" => NS)]
      ]
    end

    def direct_error(error, params = {})
      [
        400,
        ["Content-Type" => "text/plain"],
        [kv_encode(params.merge "ns" => NS, "mode" => "error", "error" => error)]
      ]
    end
    
    # Association
    def sxor(s1, s2)
      # s1 = s1.to_enum(:each_byte); s2 = s2.to_enum(:each_byte)
      s1.bytes.zip(s2.bytes).map { |x,y| (x^y).chr }.join
    end
    
    def no_encryption(mac); {"mac_key" => base64_encode(mac)} end
    
    def dh_sha1(mac, p, g, consumer_public_key)
      private_key = gen_private_key(p)
      shared = consumer_public_key ** private_key % p
      {
        "dh_server_public" => base64_encode(btwoc(g ** private_key % p)),
        "enc_mac_key" => base64_encode(sxor(OpenSSL::Digest::SHA1.new(  btwoc(shared)).digest, mac))
      }
    end
    
    def dh_sha256(mac, p, g, consumer_public_key)
      private_key = gen_private_key(p)
      shared = consumer_public_key ** private_key % p
      {
        "dh_server_public" => base64_encode(btwoc(g ** private_key)),
        "enc_mac_key" => base64_encode(sxor(OpenSSL::Digest::SHA256.new(btwoc(shared)).digest, mac))
      }
    end
    
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
    
    def base64_encode(s); [s].pack("m").rstrip end
    def base64_decode(s); s.unpack("m").first end
    def gen_private_key(p); gen_random(32).to_i(16) % p end
    def gen_handle; Time.now.utc.iso8601 + gen_random(4) end
    def gen_mac(len); gen_random(bytes) end
  end
end
