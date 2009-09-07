$: << "lib"

require "test/unit"
require "rack/test"
require "rack-openid-provider"

class YesProvider
  include Rack::OpenIdProvider::Utils
  def call(env)
    openid = env['openid.provider.req']
    redirect_positive(env, 'claimed_id' => openid['claimed_id'], 'identity' => openid['identity'] )
  end
end

class NoProvider
  include Rack::OpenIdProvider::Utils
  def call(env); redirect_negative(env) end
end

DEFAULT_REQUEST = {
  "openid.ns"         => OpenID::NS,
  "openid.mode"       => "checkid_setup",
  "openid.claimed_id" => "http://example.org",
  "openid.identity"   => "http://example.org",
  "openid.return_to"  => "http://example.org",
  "openid.assoc_handle" => "INVALIDHANDLE"
}

class TestNo < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Rack::Builder.new {
      use Rack::OpenIdProvider
      run NoProvider.new
    }.to_app
  end

  def test_checkid_setup
    post "/", DEFAULT_REQUEST
    assert last_response.redirect?
    openid = Rack::Utils.parse_query URI.parse(last_response.location).query
    assert_equal "cancel", openid["openid.mode"]
  end

  def test_checkid_immediate
    post "/", DEFAULT_REQUEST.merge("openid.mode" => "checkid_immediate")
    assert last_response.redirect?
    openid = Rack::Utils.parse_query URI.parse(last_response.location).query
    assert_equal "setup_needed", openid["openid.mode"]
  end

  def test_check_authentication
    post "/", DEFAULT_REQUEST.merge("openid.mode" => "check_authentication")
    openid = OpenID.kv_decode last_response.body
    assert_equal OpenID::NS, openid["openid.ns"]
    assert_equal "false", openid["openid.is_valid"]
    assert_nil openid["openid.invalidate_handle"]
  end

  def test_default
    get "/"
    assert last_response.not_found?
  end
end

class TestCheckId < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Rack::Builder.new {
      use Rack::OpenIdProvider
      run YesProvider.new
    }.to_app
  end

  def sxor(s1, s2); s1.bytes.zip(s2.bytes).map { |x,y| (x^y).chr }.join end

  def test_check_authentication
    post "/", DEFAULT_REQUEST
    assert last_response.redirect?
    openid = Rack::Utils.parse_query URI.parse(last_response.location).query

    assert_equal OpenID::NS, openid["openid.ns"]
    assert_equal "id_res", openid["openid.mode"]
    assert_equal "http://example.org", openid["openid.return_to"]
    assert_equal "http://example.org/", openid["openid.op_endpoint"]
    assert_equal "http://example.org", openid["openid.claimed_id"]
    assert_equal "http://example.org", openid["openid.identity"]
    assert_equal "INVALIDHANDLE", openid["openid.invalidate_handle"]
    assert_equal "op_endpoint,return_to,assoc_handle,response_nonce,identity,claimed_id", openid["openid.signed"]
    assert_match /^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ[a-z0-9]+/, openid["openid.response_nonce"]

    post "/", openid.merge( "openid.mode" => "check_authentication")
    assert last_response.ok?
    openid2 = OpenID.kv_decode last_response.body
    assert_equal OpenID::NS, openid2["openid.ns"]
    assert_equal "true", openid2["openid.is_valid"]
    assert_equal "INVALIDHANDLE", openid2["openid.invalidate_handle"]

    # Check nonce verification
    post "/", openid.merge( "openid.mode" => "check_authentication")
    assert last_response.ok?
    openid2 = OpenID.kv_decode last_response.body
    assert_equal OpenID::NS, openid2["openid.ns"]
    assert_equal "false", openid2["openid.is_valid"]
  end

  def test_associate
    private_key, public_key = OpenID::DH::SHA256.generate_pair

    post "/", 
      "openid.ns" => OpenID::NS,
      "openid.mode" => "associate",
      "openid.assoc_type" => "HMAC-SHA256",
      "openid.session_type" =>"DH-SHA256",
      "openid.dh_consumer_public" => OpenID.base64_encode(OpenID.btwoc(public_key))

    assert last_response.ok?
    openid = OpenID.kv_decode last_response.body
    assert_equal OpenID::NS, openid["openid.ns"]
    assert_equal "HMAC-SHA256", openid["openid.assoc_type"]
    assert_equal "DH-SHA256", openid["openid.session_type"]
    assert_not_nil openid["openid.assoc_handle"]
    assert_not_nil openid["openid.dh_server_public"]
    assert_not_nil openid["openid.enc_mac_key"]
    assert_not_nil openid["openid.expires_in"]

    assoc_handle = openid["openid.assoc_handle"]
    public_server_key = OpenID.ctwob(OpenID.base64_decode(openid['openid.dh_server_public']))
    shared = OpenID::DH::SHA256.compute_shared(public_server_key, private_key)
    shared_hashed = OpenSSL::Digest::SHA256.new(OpenID.btwoc(shared)).digest
    mac = sxor(OpenID.base64_decode(openid['openid.enc_mac_key']), shared_hashed)

    post "/", DEFAULT_REQUEST.merge("openid.assoc_handle" => assoc_handle)
    assert last_response.redirect?
    openid = Rack::Utils.parse_query URI.parse(last_response.location).query

    assert_equal OpenID::NS, openid["openid.ns"]
    assert_equal "id_res", openid["openid.mode"]
    assert_equal "http://example.org", openid["openid.return_to"]
    assert_equal "http://example.org/", openid["openid.op_endpoint"]
    assert_equal "http://example.org", openid["openid.claimed_id"]
    assert_equal "http://example.org", openid["openid.identity"]
    assert_equal assoc_handle, openid["openid.assoc_handle"]
    assert_equal "op_endpoint,return_to,assoc_handle,response_nonce,identity,claimed_id", openid["openid.signed"]
    assert_match /^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ[a-z0-9]+/, openid["openid.response_nonce"]
    assert_equal OpenID.gen_sig(mac, Hash[*openid.map {|k,v| [k.sub(/^openid\./, ''), v]}.flatten]), openid["openid.sig"]
  end
end
