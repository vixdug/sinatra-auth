require 'shopify_api'
require 'sinatra'
require 'httparty'
require 'dotenv'
require 'openssl'
require 'base64'
require 'pry'
Dotenv.load

API_KEY = ENV['API_KEY']
API_SECRET = ENV['API_SECRET']
APP_URL = 'https://2bc32a67.ngrok.io'

class VixApp < Sinatra::Base
    attr_reader :tokens

  def initialize
    @@tokens = {}
    super
  end

  get '/' do
     # allows your app to load in the shopify admin as opposed to a new window.
      headers({'X-Frame-Options' => ''})
     erb :index
   end

	get '/install' do
    shop = request.params['shop']
    scopes = "read_orders,read_products,write_products"

     install_url =
       "https://#{shop}/admin/oauth/authorize?client_id=#{API_KEY}&scope=#{scopes}"\
       "&redirect_uri=#{APP_URL}/auth"

     redirect install_url
	end

  get '/auth' do
     # when the merchant clicks on 'install' a params hash is generated with hmac, code, shop, and timestamp
     hmac = params['hmac']
     # assinging params as values to each key in the hash
     h = {
       shop: params['shop'],
       code: params['code'],
       timestamp: params['timestamp']
     }
     # creating an authorization string that checks to see if the hmac generated
     # by the app is the same as what Shopify provided - ensures the request came from Shopify
     h = h.map {|k,v| "#{k}=#{v}"}.sort.join("&")
     # putting 'h' through a OpenSSL method to create a digest to compare to the hmac
     # OpenSSL::Digest.new('sha256') - creates a new digest instance
     digest = OpenSSL::Digest.new('sha256')
     # creating a post request using the api info and hmac to generate an access token
     # as long as the hmac matches the digest
     digest = OpenSSL::HMAC::hexdigest(digest, API_SECRET, h)

     url = "https://#{params['shop']}/admin/oauth/access_token"
     data = {
       client_id: API_KEY,
       client_secret: API_SECRET,
       code: params['code']
     }
     # storing the result of the post request in a response variable
     # response includes the app scope, and the access token in a hash
     # the access token gives you permission to make api calls on a shop
     response = HTTParty.post(url, body: data)

     if hmac == digest
       # make sure to parse the body of the response - otherwise you will not
       # be able to properly set a token for the shop
       response = JSON.parse(response.body)
       shop = params['shop']
       token = response['access_token']
       @@tokens[shop] = token
       create_session(shop, token)
       create_webhook
       redirect "/"
        else
       status [403, "You did something wrong, you should probably check your code"]
       end
   end

   post "/webhooks/deleted_orders" do
    hmac = request.env['HTTP_X_SHOPIFY_HMAC_SHA256']
    request.body.rewind
    data = request.body.read
    webhook_ok = verify_webhook(hmac, data)
    if webhook_ok
      puts "verified webhook"
      json_data = JSON.parse(data)
      @id = json_data['id']
      puts "order id is #{id}"
    else
      puts "webhook not verified"
   end
 end

   def create_session(shop, token)
     session = ShopifyAPI::Session.new(shop, token)
     ShopifyAPI::Base.activate_session(session)
   end

   def create_webhook
    webhook = {
      topic: 'orders/delete',
      address:"#{APP_URL}/webhooks/deleted_orders",
      format: 'json'
    }
    ShopifyAPI::Webhook.create(webhook)
  end

  def verify_webhook(hmac, data)
    digest = OpenSSL::Digest.new('sha256')
    calculated_hmac = Base64.encode64(OpenSSL::HMAC.digest(digest, API_SECRET, data)).strip
    hmac == calculated_hmac
  end

 end


VixApp.run!
