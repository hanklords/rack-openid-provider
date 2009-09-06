$: << "lib"

require "test/unit"
require "rack/test"
require "rack-openid-provider"

class YesProvider
  include Rack::OpenIdProvider::Utils
  def call(env); redirect_positive(env) end
end

class NoProvider
  include Rack::OpenIdProvider::Utils
  def call(env); redirect_negative(env) end
end

DEFAULT_REQUEST = {
  "openid.ns"         => OpenID::NS,
  "openid.mode"       => "checkid_setup",
  "openid.claimed_id" => "http://example.com",
  "openid.identity"   => "http://example.com",
  "openid.return_to"  => "http://example.com"
}

class TestNo < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Rack::Builder.new {
      use Rack::OpenIdProvider
      run NoProvider.new
    }
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

  def test_default
    get "/"
    assert last_response.not_found?
  end
end

class TestYes < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Rack::Builder.new {
      use Rack::OpenIdProvider
      run YesProvider.new
    }
  end

  def test_checkid_setup
    post "/", DEFAULT_REQUEST
    assert last_response.redirect?
    openid = Rack::Utils.parse_query URI.parse(last_response.location).query
    assert_equal "id_res", openid["openid.mode"]
  end
end
