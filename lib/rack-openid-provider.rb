require 'rack'
require 'openssl'
require 'time'

module Rack
  module OpenIdProviderUtils
    NS="http://specs.openid.net/auth/2.0".freeze
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
    
    def kv_encode(h); h.map {|k,v| "openid." + k.to_s + ":" + v.to_s + 10.chr }.join end
#    def kv_decode(s); Hash[*s.split(10.chr).map {|l| l.split(":", 2) }.flatten] end
    
    def base64_encode(s); [s].pack("m").rstrip end
    def base64_decode(s); s.unpack("m").first end
      
    def hmac_sha1(mac, value)
      OpenSSL::HMAC.new(mac, OpenSSL::Digest::SHA1.new).update(value)
    end
    
    def hmac_sha256(mac, value)
      OpenSSL::HMAC.new(mac, OpenSSL::Digest::SHA256.new).update(value)
    end
  end
  
  class OpenIdProvider
    DH_MODULUS=0XDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
    DH_GEN=2
    include OpenIdProviderUtils

    def initialize(app); @app = app end

    def call(env)
      req = Request.new(env)
      env['openid.provider.request.params'] = open_id_params(req.params)
      case req['openid.mode']
      when 'associate'
        associate(env, env['openid.provider.request.params'])
      when 'checkid_immediate', 'checkid_setup'
        # Requesting Authentication
      when 'check_authentication'
        # Verifying Signatures
      else
        @app.call(env)
      end
    end

#    private
    def direct_response(params)
      [
        200,
        ["Content-Type" => "text/plain"],
        [kv_encode({"ns" => NS}.merge params)]
      ]
    end
    
    def direct_error(error, params = {})
      [
        400,
        ["Content-Type" => "text/plain"],
        [kv_encode({"ns" => NS, "error" => error}.merge params)]
      ]
    end
    
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
      raise unless len
      
      
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
        raise if not consumer_public_key
        dh_sha256(mac, p, g, consumer_public_key)
      when "DH-SHA1" 
        raise if not consumer_public_key
        dh_sha1(mac, p, g, consumer_public_key)
      when "no-encryption" 
        no_encryption(mac)
      end
      
      direct_response r
    end

    def open_id_params(params)
      openid_params = {}
      params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
      openid_params
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
    
    def gen_random(bytes); OpenSSL::Random.random_bytes(bytes).unpack("H*")[0] end
    def gen_private_key(p); gen_random(32).to_i(16) % p end
    def gen_handle; Time.now.utc.iso8601 + gen_random(4) end
    def gen_mac(len); gen_random(bytes) end
  end
end

p Rack::OpenIdProvider.new(nil).kv_encode(:text => "value", :int => 3456734)

p Rack::OpenIdProvider.new(nil).base64_encode("value")
p Rack::OpenIdProvider.new(nil).base64_decode("dmFsdWU=")

p Rack::OpenIdProvider.new(nil).gen_handle