require 'sinatra/base'
require 'rack/openid-provider'

module Sinatra
  module OpenIDProvider
    
    module Helpers
      def openid; Rack::OpenIDRequest.new(env) end
      def openid_html_fields(h) Rack::OpenIDRequest.gen_html_fields(h) end
    end
   
    def checkid_setup(&block)
      get  "/", :openid_mode => "checkid_setup", &block
      post "/", :openid_mode => "checkid_setup", &block
    end
       
    def checkid_immediate(&block)
      get  "/", :openid_mode => "checkid_immediate", &block
      post "/", :openid_mode => "checkid_immediate", &block
    end
    
    def self.registered(app)
      app.helpers OpenIDProvider::Helpers
      app.set(:openid_mode) { |value| condition { openid.mode == value } }
    end
  end
  
  register OpenIDProvider
end
