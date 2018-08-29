module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # For more information on the Paytrace Gateway please visit their {Integration Center}[https://developers.paytrace.com]
    #
    # The login and password are not the username and password you use to 
    # login to the Authorize.Net Merchant Interface. Instead, you will 
    # use the API Login ID as the login and Transaction Key as the 
    # password.
    # 
    # ==== How to Get Your API Login ID and Transaction Key
    #
    # 1. Log into the Merchant Interface
    # 2. Select Settings from the Main Menu
    # 3. Click on API Login ID and Transaction Key in the Security section
    # 4. Type in the answer to the secret question configured on setup
    # 5. Click Submit
    # 
    # ==== Automated Recurring Billing (ARB)
    # 
    # Automated Recurring Billing (ARB) is an optional service for submitting and managing recurring, or subscription-based, transactions.
    # 
    # To use recurring, update_recurring, and cancel_recurring ARB must be enabled for your account.
    # 
    # Information about ARB is available on the {Authorize.Net website}[http://www.authorize.net/solutions/merchantsolutions/merchantservices/automatedrecurringbilling/].
    # Information about the ARB API is available at the {Authorize.Net Integration Center}[http://developer.authorize.net/]
    class PayTraceGateway < Gateway
      require 'rest-client'

      BASE_URL = 'https://api.paytrace.com'

      # Creates a new PayTraceGateway
      #
      def initialize(options = {})
        requires!(options, :login, :password, :integrator_id)
        @options = options
        super
      end


      def auth_token
        response = RestClient.post(BASE_URL + '/oauth/token', {
          :grant_type => 'password',
          :username => @options[:login],
          :password => @options[:password]})

        JSON.parse(response)                                  
      end

      def auth_failed?(token)
        token['error'].present?
      end

      def auth_failed_response(token)
        ActiveMerchant::Billing::Response.new(token['access_token'].present?,token['error_description'],token,token)      
      end

      # Performs an authorization, which reserves the funds on the customer's credit card, but does not
      # charge the card.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be authorized. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      #  # Optional parameters:
      # * *:billing_name* -- the billing name for this transaction
      # * *:billing_address* -- the billing street address for this transaction
      # * *:billing_address2* -- the billing street address second line (e.g., apartment, suite) for this transaction
      # * *:billing_city* -- the billing city for this transaction
      # * *:billing_state* -- the billing state for this transaction
      # * *:billing_postal_code* -- the billing zip code for this transaction
      # * *:billing_country* -- the billing country for this transaction
      # * *:shipping_name* -- the shipping name for this transaction
      # * *:shipping_address* -- the shipping street address for this transaction
      # * *:shipping_address2* -- the shipping street address second line (e.g., apartment, suite) for this transaction
      # * *:shipping_city* -- the shipping city for this transaction
      # * *:shipping_state* -- the shipping state for this transaction
      # * *:shipping_postal_code* -- the shipping zip code for this transaction
      # * *:shipping_region* -- the shipping region (e.g. county) for this transaction
      # * *:shipping_country* -- the shipping country for this transaction
      # * *:email* -- the customer email for this transaction
      # * *:csc* -- credit card security code (customer ID token or referenced transaction sale)
      # * *:invoice* -- an internal invoice number (customer ID token or referenced transaction sale)
      # * *:description* -- a description of the sale (customer ID token or referenced transaction sale)
      # * *:tax_amount* -- the amount of tax on the sale (customer ID token or referenced transaction sale)
      # * *:customer_reference_id* -- a customer reference ID (customer ID token or referenced transaction sale)
      # * *:discretionary_data* -- a hash of optional discretionary data to attach to this transaction
      # * *:return_clr* -- if set to "Y", card level results will be returned w/ the response. Card level results include whether or not the card is a consumer, purchasing, check, rewards, etc. account. Card level results are only returned with requests to process sales or authorizations through accounts on the TSYS/Vital, Heartland, Global, Paymentech, and Trident networks.(customer ID token sale)
      # * *:custom_dba* -- optional value that is sent to the cardholder’s issuer and overrides the business name stored in PayTrace. Custom DBA values are only used with requests to process sales or authorizations through accounts on the TSYS/Vital, Heartland, and Trident networks (customer ID token sale)
      # * *:enable_partial_authentication* -- flag that must be set to ‘Y’ in order to support partial autho
      def authorize(money, creditcard, options = {})
        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)

        headers = {:Authorization => "Bearer #{token['access_token']}"}

        body = {
          :amount => money / 100.0,
          :credit_card => { 
            :number => creditcard.number,
            :expiration_month => creditcard.month.to_i.to_s,
            :expiration_year => (creditcard.year.to_i + 2000).to_s
          },
          :integrator_id => @options[:integrator_id],
          :csc => creditcard.verification_value,
          :billing_address => {
            :name => billing_address[:name],
            :street_address => billing_address[:address1],
            :street_address2 => billing_address[:address2],
            :city => billing_address[:city],
            :state => billing_address[:state],
            :zip => billing_address[:zip]
          },
        }

        response = RestClient.post(BASE_URL + '/v1/transactions/authorization/keyed', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,
          :authorization => result[:transaction_id],
          :fraud_review => (result[:csc_response] != 'Match'),
          :avs_result => result[:avs_response],
          :cvv_result => result[:csc_response])
      end

      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be purchased. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      def purchase(money, creditcard, options = {})

        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)
        
        headers = {:Authorization => "Bearer #{token['access_token']}"}

        billing_address = options[:billing_address]

        body = {
          :amount => money / 100.0,
          :credit_card => { 
            :number => creditcard.number,
            :expiration_month => creditcard.month.to_i.to_s,
            :expiration_year => (creditcard.year.to_i + 2000).to_s
          },
          :integrator_id => @options[:integrator_id],
          :csc => creditcard.verification_value,
          :billing_address => {
            :name => billing_address[:name],
            :street_address => billing_address[:address1],
            :street_address2 => billing_address[:address2],
            :city => billing_address[:city],
            :state => billing_address[:state],
            :zip => billing_address[:zip]
          },
        }

        response = RestClient.post(BASE_URL + '/v1/transactions/sale/keyed', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,
          :authorization => result[:transaction_id],
          :fraud_review => (result[:csc_response] != 'Match'),
          :avs_result => result[:avs_response],
          :cvv_result => result[:csc_response])
      end

      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      def capture(money, authorization, options = {})

        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)
        
        headers = {:Authorization => "Bearer #{token['access_token']}"}

        body = { :transaction_id => authorization }

        response = RestClient.post(BASE_URL + '/v1/transactions/authorization/capture', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,
          :authorization => result[:transaction_id])

      end

      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      def void(authorization, options = {})
        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)
        
        headers = {:Authorization => "Bearer #{token['access_token']}"}

        body = { :transaction_id => authorization }

        response = RestClient.post(BASE_URL + '/v1/transactions/void', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,
          :authorization => result[:transaction_id])
      end

      # Credit an account.
      #
      # This transaction is also referred to as a Refund and indicates to the gateway that
      # money should flow from the merchant to the customer.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be credited to the customer. Either an Integer value in cents or a Money object.
      # * <tt>identification</tt> -- The ID of the original transaction against which the credit is being issued.
      # * <tt>options</tt> -- A hash of parameters.
      #
      # ==== Options
      #
      # * <tt>:card_number</tt> -- The credit card number the credit is being issued to. (REQUIRED)
      def credit(money, identification, options = {})
        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)
        
        headers = { :Authorization => "Bearer #{token['access_token']}"}
        body = { :amount => money/100.0, :transaction_id => identification }

        response = RestClient.post(BASE_URL + '/v1/transactions/refund/for_transaction', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,
          :authorization => result[:transaction_id])
      end

      def settle
        token = auth_token
        return auth_failed_response(token) if auth_failed?(token)
        
        headers = { :Authorization => "Bearer #{token['access_token']}"}
        body = {}

        response = RestClient.post(BASE_URL + '/v1/transactions/settle', body, headers) {|response, request, result| response }
        result = JSON.parse(response)

        ActiveMerchant::Billing::Response.new(result['success'],result['status_message'],result,result)
      end
    end
  end
end
