class AuthorizationEndpoint
  attr_accessor :_request_,
    :account,
    :client,
    :options,
    :redirect_uri,
    :request_object,
    :request_uri,
    :response_type,
    :scopes

  def initialize(acct, params={})
    self.options = HashWithIndifferentAccess.new(
      allow_approval: false,
      user_approved: false
    ).merge(params)

    self.account = acct
  end

  def call(env)
    rack_app.call(env)
  end

  def login_expired?
    max_age && self.account.last_logged_in_at < max_age.seconds.ago
  end

  def max_age
    request_object.try(:id_token).try(:max_age)
  end

  def allow_approval
    options[:allow_approval]
  end

  def user_approved
    options[:user_approved]
  end

  private
  def rack_app
    Rack::OAuth2::Server::Authorize.new do |req, res|
      self.client = Client.find_by_identifier(req.client_id)
      self.scopes = Scope.where(name: req.scope)
      self._request_ = req.request
      self.request_uri = req.request_uri
      self.redirect_uri = res.redirect_uri = req.verify_redirect_uri!(client.redirect_uris)
      self.request_object = if self._request_.present?
                              OpenIDConnect::RequestObject.decode req.request, nil # client.secret
                            elsif self.request_uri.present?
                              OpenIDConnect::RequestObject.fetch req.request_uri, nil # client.secret
                            end

      nonce_missing = res.protocol_params_location == :fragment && req.nonce.blank?
      unknown_scopes = req.scope - self.scopes.map(&:name)

      req.bad_request! if self.client.blank?
      req.invalid_request!('Nonce required') if nonce_missing
      req.invalid_scope!("Unknown scope(s): #{unknown_scopes.join(' ')}") if unknown_scopes.present?
      req.unsupported_response_type! unless Client.can_handle_response_type?(req.response_type)
      req.access_denied! if allow_approval && !user_approved

      if allow_approval && user_approved
        approve!(req,res)
      else
        self.response_type = req.response_type
      end
    end
  end

  def approve!(req, res)
    response_types = Array(req.response_type)

    set_code(req,res) if response_types.include? :code
    set_access_token(req,res) if response_types.include? :token
    set_id_token(req,res) if response_types.include? :id_token

    res.approve!
  end

  def set_code(req,res)
    authorization = account.authorizations.create!(
      client: client,
      redirect_uri: res.redirect_uri,
      nonce: req.nonce
    )

    authorization.scopes << scopes

    if request_object
      authorization.create_authorization_request_object!(
        request_object: RequestObject.new(
          jwt_string: request_object.to_jwt(client.secret, :HS256)
        )
      )
    end

    res.code = authorization.code
  end

  def set_access_token(req,res)
    access_token = account.access_tokens.create!(client: client)
    access_token.scopes << scopes

    if request_object
      access_token.create_access_token_request_object!(
        request_object: RequestObject.new(
          jwt_string: request_object.to_jwt(client.secret, :HS256)
        )
      )
    end

    res.access_token = access_token.to_bearer_token
  end

  def set_id_token(req,res)
    _id_token_ = account.id_tokens.create!(
      client: client,
      nonce: req.nonce
    )

    if request_object
      _id_token_.create_id_token_request_object!(
        request_object: RequestObject.new(
          jwt_string: request_object.to_jwt(client.secret, :HS256)
        )
      )
    end

    res.id_token = _id_token_.to_jwt(
      code: (res.respond_to?(:code) ? res.code : nil),
      access_token: (res.respond_to?(:access_token) ? res.access_token : nil)
    )
  end
end
