ConnectOp::Application.routes.draw do
  resource :session,   only: :destroy
  resource :dashboard, only: :show

  resources :clients, except: :show
  resources :authorizations, only: [:new, :create]

  namespace :connect do
    resource :fake,     only: :create
    resource :facebook, only: :show
    resource :google,   only: :show
    resource :client
  end

  root to: 'top#index'

  post 'access_tokens', to: proc { |env| TokenEndpoint.new.call(env) }

  match '.well-known/:id', to: 'discovery#show'
  match 'user_info', to: 'user_info#show', :via => [:get, :post]
  match 'id_token', to: proc { |env| CheckSessionEndpoint.new.call(env) }, :via => [:get, :post]
  get 'cert.pem', to: proc { |env| [200, {}, [IdToken.config[:cert].to_s]] }
end
