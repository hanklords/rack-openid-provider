module ::Rack
class OpenIDRequest
  class Sreg
    FIELDS = %w(required optional policy_url).freeze
    FIELD_SIGNED = %w(nickname email fullname dob gender postcode country language timezone).freeze
    FIELD_SIGNED.each { |field| OpenIDProvider::FIELD_SIGNED << "sreg.#{field}" }
    
    def initialize(params) @params = params end
    def required; (@params["sreg.required"] || "").split(",") end
    def optional; (@params["sreg.optional"] || "").split(",") end
    def requested; optional + required end
    def policy_url; @params["sreg.policy_url"] end
  end
  
  def sreg; @env['openid.provider.request.params.sreg'] ||= Sreg.new(params) end
end

class OpenIDResponse
  class Sreg
    def initialize(params) @params = params end
    OpenIDRequest::Sreg::FIELD_SIGNED.each { |field| 
      class_eval %{def #{field}; @params["sreg.#{field}"] end}
      class_eval %{def #{field}=(v); @params["sreg.#{field}"] = v end}
    }
  end
  
  def sreg; @sreg ||= Sreg.new(params) end
end
end
