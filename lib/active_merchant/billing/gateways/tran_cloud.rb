module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # For more information on the TranCloud Gateway please visit their {Integration Center}[https://www.dsidevportal.com]
    #
    # TranCloud is a product of {DataCap Systems}[https://www.datacapsystems.com/mobile-and-cloud-based-point-of-sale]
    #
    # WARNING: There is no TEST URL - all development/testing must be done against production system.
    #
    # https://www.dsidevportal.com for documentation and support
    #
    class TranCloudGateway < Gateway
      require 'rest-client'

      TEST_URL = 'https://trancloud.dsipscs.com/ProcessEMVTransaction'
      LIVE_URL = 'https://trancloud.dsipscs.com/ProcessEMVTransaction'


      # Creates a new PayTraceGateway
      #
      def initialize(options = {})
        requires!(options, :test, :merchant_id, :trancloud_account_id, :trancloud_auth, :operator_id, :mac_address, :trancloud_device_id, :lane_id)
        @options = options
        if @options[:response].present?
          response = JSON.parse(@options[:response], :symbolize_names => true)
          response = response[:RStream] if response.present? && response[:RStream].present?
          @options = @options.merge(response)
        end
        super
      end

      def url
        @options[:test] ? TEST_URL : LIVE_URL
      end

      def basic_auth_token
        Base64.encode64("#{@options[:trancloud_account_id]}:#{@options[:trancloud_auth]}")
      end

      def headers
        headers = {
          :authorization => "Basic #{basic_auth_token}",
          :content_type => :json, 
          :accept => :json
        }
      end

      def credentials
        @options.dup
      end

      def request_failed?(doc)
        doc[:DSIXReturnCode] != '000000' || doc[:CmdStatus] == 'Error' || doc[:CmdStatus] == 'Declined'
      end

      def request_failed_response(doc)
        ActiveMerchant::Billing::Response.new(
          false,
          doc[:ResponseOrigin] + ': ' + (doc[:TextResponse] || doc[:CmdStatus] || ''),
          {},
          :raw => doc)    
      end

      # Performs an authorization, which reserves the funds on the customer's credit card, but does not
      # charge the card.
      #
      def authorize(money, creditcard, options = {})
        reset
      end

      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      def purchase(money, creditcard, options = {})
        transRequest = basic_request(:EMVSale)
        trs = transRequest[:TStream][:Transaction]

        trs[:CollectData] = :CardholderName
        trs[:Amount] = {:Purchase => ('%.2f' % (money / 100.0))}
        trs[:PartialAuth] = 'Disallow'
        trs[:LaneID] = @options[:lane_id]
        trs[:RecordNo] = :RecordNumberRequested
        trs[:Frequency] = 'Recurring'
        trs[:OKAmount] = 'Disallow'
        trs[:InvoiceNo] = @options[:invoice_no]
        trs[:RefNo] = @options[:invoice_no]
        trs[:CardType] = 'Credit'
        trs[:Account] = @options[:Account] if @options[:Account].present?

        logger.debug 'REQUEST: ' + JSON.pretty_generate(transRequest)
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }

        #values = response[:RStream].reject { |k,v| (k.to_s =~ /Line/) === 0 }
        values = response[:RStream]
        logger.debug 'RESPONSE: ' + JSON.pretty_generate(response)
        return request_failed_response(values) if request_failed?(values)
        
        card_holder_name = {:name_first => '', :name_last => ''}

        if values[:CardholderName].present?
          pair = values[:CardholderName].split('/').collect{|s| s.strip }.reject{|s| s.empty? }
          
          if pair.size == 2
             card_holder_name = {:name_first => pair[1].split('.').first.strip, :name_last => pair[0].strip}
          elsif pair.size > 1
            pair = pair.first.split(' ')
            card_holder_name = { :name_first => pair.first.strip, :name_last => pair.last.strip }
          end  
        end
          values[:authorization] = values[:RecordNo]
          values[:auth_code] = values[:AuthCode]

        result = ActiveMerchant::Billing::Response.new(
          true,
          (values[:TextResponse] || values[:CmdStatus] || ''),
          values,
          :authorization => values[:InvoiceNo],
          :auth_code => values[:AuthCode],
          :card_number => values[:AcctNo],
          :card_holder_name => values[:CardholderName],
          :card_type => values[:CardType],
          :card_entry_method => values[:EntryMethod],
          :card_issuer => values[:ApplicationLabel],
          :card_holder_name_first => card_holder_name[:name_first] || '',
          :card_holder_name_last => card_holder_name[:name_last] || '',
          :request => transRequest.to_json,
          :response => response.to_json
          )

          emv_param_download if values[:PostProcess] == 'EMVParamDownloadRequired'

        result
      end

      

      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      def capture(money, authorization, options = {})
        reset
      end

      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      def void(authorization, options = {})

        transRequest = @options[:RecordNo].present? ? basic_request(:VoidSaleByRecordNo) : basic_request(:EMVVoidSale)
        trs = transRequest[:TStream][:Transaction]
        # Send <RefNo>, <AuthCode>, <ProcessData>, and <AcqRefData> from response

        money = options[:amount]
        trs[:RecordNo] = @options[:RecordNo] if @options[:RecordNo].present?
        trs[:TranType] = 'Credit' if @options[:RecordNo].present?
        trs[:Amount] = {:Purchase => ('%.2f' % (money / 100.0))}
        trs[:InvoiceNo] = options[:InvoiceNo] || @options[:InvoiceNo]
        trs[:RefNo] = options[:RefNo] || @options[:RefNo] || trs[:InvoiceNo]
        trs[:AuthCode] = @options[:AuthCode]
        trs[:AcqRefData] = options[:AcqRefData] || @options[:AcqRefData]
        trs[:Account] = @options[:Account] if @options[:Account].present? && !@options[:RecordNo].present?
        trs[:OKAmount] = 'Disallow'
        if options[:ProcessData].present? || @options[:ProcessData].present?
          trs[:ProcessData] = options[:ProcessData] || @options[:ProcessData]
        end
        trs.delete(:PinPadIpAddress) if @options[:RecordNo].present?
        trs.delete(:Duplicate)

        logger.debug 'REQUEST: ' + JSON.pretty_generate(transRequest)

        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }

        values = response[:RStream].reject { |k,v| k.to_s[0..3] == 'Line' }
        logger.debug 'RESPONSE: ' + JSON.pretty_generate(response)

        return request_failed_response(values) if request_failed?(values)

        card = {
          :card_number => values[:AcctNo], 
          :card_type => values[:CardType],
          :card_exp => values[:ExpDate]
          }

          values[:authorization] = values[:RecordNo]
          values[:auth_code] = values[:AuthCode]
          values[:credit_card] = card

        result = ActiveMerchant::Billing::Response.new(
          true,
          (values[:TextResponse] || values[:CmdStatus] || ''),
          values,
          :authorization => values[:InvoiceNo],
          :auth_code => values[:AuthCode],
          :request => transRequest.to_json,
          :response => response.to_json
          )

        # if values[:PostProcess] == 'EMVParamDownloadRequired' 
        #   emv_param_download 
        #   reset
        # else
        #   reset
        # end

        result
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
        transRequest = @options[:RecordNo].present? ? basic_request(:ReturnByRecordNo) : basic_request(:EMVReturn)
        trs = transRequest[:TStream][:Transaction]

        if @options[:RecordNo].present?
          trs[:RecordNo] = @options[:RecordNo]
          trs[:Frequency] = 'Recurring'
          trs[:TranType] = 'Credit'
          trs.delete(:PinPadIpAddress)
        else
          trs[:Account] = @options[:Account] if @options[:Account].present?
        end
        trs[:Amount] = {:Purchase => ('%.2f' % (money / 100.0))}
        trs[:InvoiceNo] = options[:InvoiceNo] || @options[:InvoiceNo]
        trs[:RefNo] = options[:RefNo] || @options[:RefNo] || trs[:InvoiceNo]
        trs[:AuthCode] = @options[:AuthCode]
        trs[:AcqRefData] = options[:AcqRefData] || @options[:AcqRefData]
        trs[:OKAmount] = 'Disallow'
        trs[:ProcessData] = options[:ProcessData] if options[:ProcessData].present?
        trs[:ProcessData] ||= @options[:ProcessData] if @options[:ProcessData].present?
        trs.delete(:Duplicate)

        logger.debug 'REQUEST: ' + JSON.pretty_generate(transRequest)
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }
        
        values = response[:RStream].reject { |k,v| k.to_s[0..3] == 'Line' }
        logger.debug 'RESPONSE: ' + JSON.pretty_generate(response)

        return request_failed_response(values) if request_failed?(values)

        values[:authorization] = values[:RecordNo]
        values[:auth_code] = values[:AuthCode]

        result = ActiveMerchant::Billing::Response.new(
          true,
          (values[:TextResponse] || values[:CmdStatus] || ''),
          values,
          :authorization => values[:InvoiceNo],
          :auth_code => values[:AuthCode],
          :request => transRequest.to_json,
          :response => response.to_json
          )

        result
      end

      def reset
        transRequest = basic_request(:EMVPadReset)
        trs = transRequest[:TStream][:Transaction]
        logger.debug 'REQUEST: ' + transRequest.to_json
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }
        logger.debug 'RESPONSE: ' + response.to_json
        
        values = response[:RStream].reject { |k,v| (k.to_s =~ /Line/) === 0 }
        return request_failed_response(values) if request_failed?(values)

        ActiveMerchant::Billing::Response.new(
          values[:DSIXReturnCode],
          (values[:ResponseOrigin] + ': ' + (values[:TextResponse] || values[:CmdStatus] || '')),{},
          :request => transRequest.to_json,
          :response => response[:RStream].to_json)
      end

      def emv_param_download
        transRequest = basic_request(:EMVParamDownload, :Admin)
        logger.debug 'REQUEST: ' + transRequest.to_json
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }
        logger.debug 'RESPONSE: ' + response.to_json

        values = response[:RStream].reject { |k,v| (k.to_s =~ /Line/) === 0 }
        return request_failed_response(values) if request_failed?(values)

        ActiveMerchant::Billing::Response.new(
          true,
          (values[:ResponseOrigin] + ': ' + (values[:TextResponse] || values[:CmdStatus] || '')),{},
          :request => transRequest.to_json,
          :response => response.to_json
)
      end

      def basic_request(tran_code, request_type = :Transaction)
        transRequest = { :TStream => { request_type => {} } }
        trs = transRequest[:TStream][request_type]
        logger.debug @options.to_json
        trs[:MerchantID] = @options[:merchant_id]
        trs[:OperatorID] = @options[:operator_id]
        trs[:TranDeviceID] = @options[:trancloud_device_id]
        trs[:LaneID] = @options[:lane_id]
        #trs[:POSPackageID] = 'WaResClient:1.0'
        trs[:SecureDevice] = 'CloudEMV2'#'EMV_VX805_ELAVON';
        trs[:TranCode] = tran_code
        trs[:SequenceNo] = '0010010010'
        trs[:Duplicate] = 'None'
        trs[:TerminalID] = 'BOEING STORE FUTURE OF FLIGHT'
        #trs[:PinPadMACAddress] = @options[:mac_address]
        trs[:PinPadIpAddress] = @options[:ip_address]
        transRequest
      end

      # pointless because all calls are blocking
      def cancel()
        transRequest = basic_request(:TransactionCancel, :Admin)
        trs = transRequest[:TStream][:Admin]
        logger.debug 'REQUEST: ' + transRequest.to_json
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }
        logger.debug 'RESPONSE: ' + response.to_json
        
        values = response[:RStream].reject { |k,v| (k.to_s =~ /Line/) === 0 }
        return request_failed_response(values) if request_failed?(values)

        ActiveMerchant::Billing::Response.new(
          values[:DSIXReturnCode],
          (values[:ResponseOrigin] + ': ' + (values[:TextResponse] || values[:CmdStatus] || '')),{},
          :raw => values)
      end

      def batch_summary()
        transRequest = basic_request(:BatchSummary, :Admin)
        trs = transRequest[:TStream][:Admin]
        trs[:TranType] = 'Administrative'
        logger.debug 'REQUEST: ' + transRequest.to_json
        response = RestClient::Request.execute(
          :method => :post, 
          :url => url, 
          :headers => headers, 
          :payload => transRequest.to_json, 
          :timeout => 120) {|response, request, result| JSON.parse(response, :symbolize_names => true) }
        logger.debug 'RESPONSE: ' + response.to_json
        
        values = response[:RStream].reject { |k,v| (k.to_s =~ /Line/) === 0 }
        return request_failed_response(values) if request_failed?(values)

        ActiveMerchant::Billing::Response.new(
          values[:DSIXReturnCode],
          (values[:ResponseOrigin] + ': ' + (values[:TextResponse] || values[:CmdStatus] || '')),{},
          :request => transRequest.to_json,
          :response => response.to_json
)
      end


      def settle
      end

    end
  end
end
