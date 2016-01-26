# encoding: utf-8
require 'validates_email_format_of/version'

module ValidatesEmailFormatOf
  def self.load_i18n_locales
    require 'i18n'
    I18n.load_path += Dir.glob(File.expand_path(File.join(File.dirname(__FILE__), '..', 'config', 'locales', '*.yml')))
  end

  require 'resolv'
  require 'net/telnet'
  require 'timeout'
  require 'faker'

  LocalPartSpecialChars = /[\!\#\$\%\&\'\*\-\/\=\?\+\-\^\_\`\{\|\}\~]/

  @@default_options = {}
  def self.default_options
    @@default_options
  end

  def self.get_mx_records(email, options={})
  	opts = self.get_options(options)
    email = self.sanitize_email(email)
  	
  	domain_override = opts[:email_domain].is_a?(Proc) ? opts[:email_domain].call(email) : opts[:email_domain]
    domain = (domain_override.is_a?(String)) ? domain_override : email.to_s.downcase.split('@', 2)[1]
    Resolv::DNS.open do |dns|
      dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
    end
  end

  def self.ping_email(email, email_host)
    begin
      telnet = Net::Telnet.new(
                "Host" => email_host,
                "Port" => 25,
                "Prompt" => /^\d{3}\s/
                )
      telnet.waitfor 'Match' => /^\d{3}\s/
      [
        "HELO #{ self.helo_domain }",
        "mail from:<#{ Faker::Internet.safe_email }>",
        "rcpt to:<#{ email }>",
      ].all? { |cmd| telnet.cmd(cmd) =~ /^2\d{2}\s/ }
    rescue Exception => e
      puts e.message
      nil
    ensure
      telnet.close rescue nil
    end

  end

  def self.validate_email_domain(email, options={})
    mxrs = self.get_mx_records(email, options)
    [mxrs.size > 0, mxrs]
  end

  def self.validate_email_pingable(email, mxrs=nil, options={})
    email = self.sanitize_email(email)
    mxrs = self.get_mx_records(email, options) unless mxrs
    mxrs.sort! {|x, y| x.preference <=> y.preference}

    result = nil
    mxrs.each { |mxr|
      result = self.ping_email(email, mxr.exchange.to_s)
      return result unless result.nil?
    }
    result
  end

  # Validates whether the specified value is a valid email address.  Returns nil if the value is valid, otherwise returns an array
  # containing one or more validation error messages.
  #
  # Configuration options:
  # * <tt>message</tt> - A custom error message (default is: "does not appear to be valid")
  # * <tt>check_mx</tt> - Check for MX records (default is false)
  # * <tt>check_mx_ping</tt> - Ping email address on SMTP server according to MX records (default is false)
  # * <tt>check_mx_timeout</tt> - Timeout for MX records processing (default is nil)
  # * <tt>mx_timeout_error_important</tt> - Return error in case DNS or SMTP total time exceeds timeout (default is false)
  # * <tt>mx_message</tt> - A custom error message when a MX record validation fails (default is: "is not routable.")
  # * <tt>mx_ping_message</tt> - A custom error message when a MX record e-mail address pinging fails (default is: "is not pingable.")
  # * <tt>mx_timeout_message</tt> - A custom error message when a MX record e-mail address validation and pinging timeouts (default is: "MX record processing timed out.")
  # * <tt>with</tt> The regex to use for validating the format of the email address (deprecated)
  # * <tt>local_length</tt> Maximum number of characters allowed in the local part (default is 64)
  # * <tt>domain_length</tt> Maximum number of characters allowed in the domain part (default is 255)
  # * <tt>email_domain</tt> Domain name override to search MX records. Must be String or Proc that returns String. (default is nil)
  # * <tt>generate_message</tt> Return the I18n key of the error message instead of the error message itself (default is false)
  # * <tt>strict</tt> Use strict regex for e-mail validation (default is true)
  def self.validate_email(email, options={})
      opts = self.get_options(options)

      return [ opts[:message] ] unless self.validate_email_format(email, opts: opts)

      if opts[:check_mx] || opts[:check_mx_ping]
        begin
          Timeout.timeout(opts[:timeout]) {
            validity, mxrs = self.validate_email_domain(email)
            unless validity
              return [ opts[:mx_message] ]
            end

            if opts[:check_mx_ping]
              validity = self.validate_email_pingable(email, mxrs)
              if not validity.nil? and not validity
                return [ opts[:mx_ping_message] ]
              end
            end
          }
        rescue Timeout::Error => e
          if opt[:mx_timeout_error_important]
            return [ opt[:mx_timeout_message] ]
          end
        end
      end

      return nil    # represents no validation errors
  end

  def self.validate_email_format(email, options={})
      opts = self.get_options(options)
      email = self.sanitize_email(email)

      begin
        domain, local = email.reverse.split('@', 2)
      rescue
        return false
      end

      return false if email =~ /[^ -~?-?]/

      # need local and domain parts
      return false unless local and not local.empty? and domain and not domain.empty?

      # check lengths
      return false unless domain.length <= opts[:domain_length] and local.length <= opts[:local_length]

      local.reverse!
      domain.reverse!

      if opts.has_key?(:with) # holdover from versions <= 1.4.7
        return false unless email =~ opts[:with]
      else
        return false unless self.validate_local_part_syntax(local, opts[:strict]) and self.validate_domain_part_syntax(domain)
      end

      return true
  end


  def self.validate_local_part_syntax(local, strict=true)
    in_quoted_pair = false
    in_quoted_string = false

    (0..local.length-1).each do |i|
      ord = local[i].ord

      # accept anything if it's got a backslash before it
      if in_quoted_pair
        in_quoted_pair = false
        next
      end

      # backslash signifies the start of a quoted pair
      if ord == 92 and i < local.length - 1
        return false if not in_quoted_string # must be in quoted string per http://www.rfc-editor.org/errata_search.php?rfc=3696
        in_quoted_pair = true
        next
      end

      # double quote delimits quoted strings
      if ord == 34
        in_quoted_string = !in_quoted_string
        next
      end

      next if local[i,1] =~ /[a-z0-9]/i
      next if local[i,1] =~ LocalPartSpecialChars
      next unless strict

      # period must be followed by something
      if ord == 46
        return false if i == 0 or i == local.length - 1 # can't be first or last char
        next unless local[i+1].ord == 46 # can't be followed by a period
      end

      return false
    end

    return false if in_quoted_string # unbalanced quotes

    return true
  end

  def self.validate_domain_part_syntax(domain)
    parts = domain.downcase.split('.', -1)

    return false if parts.length <= 1 # Only one domain part

    # Empty parts (double period) or invalid chars
    return false if parts.any? {
      |part|
        part.nil? or
        part.empty? or
        not part =~ /\A[[:alnum:]\-]+\Z/ or
        part[0,1] == '-' or part[-1,1] == '-' # hyphen at beginning or end of part
    }

    # ipv4
    return true if parts.length == 4 and parts.all? { |part| part =~ /\A[0-9]+\Z/ and part.to_i.between?(0, 255) }

    return false if parts[-1].length < 2 or not parts[-1] =~ /[a-z\-]/ # TLD is too short or does not contain a char or hyphen

    return true
  end

  private
    DEFAULT_MESSAGE = "does not appear to be valid"
    DEFAULT_MX_MESSAGE = "is not routable"
    DEFAULT_MX_PING_MESSAGE = "is not pingable"
    DEFAULT_MX_TIMEOUT_MESSAGE = "MX record processing timed out"
    ERROR_MESSAGE_I18N_KEY = :invalid_email_address
    ERROR_MX_MESSAGE_I18N_KEY = :email_address_not_routable
    ERROR_MX_PING_MESSAGE_I18N_KEY = :email_address_not_pingable
    ERROR_MX_TIMEOUT_MESSAGE_I18N_KEY = :mx_timeout

    def self.get_options(options= {})
      if options[:opts]
        options[:opts]
      else
        default_options = { :message => get_message(ERROR_MESSAGE_I18N_KEY, DEFAULT_MESSAGE, options),
                            :check_mx => false,
                            :check_mx_ping => false,
                            :check_mx_timeout => nil,
                            :mx_timeout_error_important => false,
                            :mx_message => get_message(ERROR_MX_MESSAGE_I18N_KEY, DEFAULT_MX_MESSAGE, options),
                            :mx_ping_message => get_message(ERROR_MX_PING_MESSAGE_I18N_KEY, DEFAULT_MX_PING_MESSAGE, options),
                            :mx_timeout_message => get_message(ERROR_MX_TIMEOUT_MESSAGE_I18N_KEY, DEFAULT_MX_TIMEOUT_MESSAGE, options),
                            :domain_length => 255,
                            :email_domain => nil,
                            :local_length => 64,
                            :generate_message => false,
                            :strict => true
                            }
        default_options.merge!(@@default_options)

        default_options.merge(options)
      end
    end

    def self.sanitize_email email
      email = email.strip if email
    end

    def self.get_message i18n_key, default_message, options
      options[:generate_message] ? i18n_key : (defined?(I18n) ? I18n.t(i18n_key, :scope => [:activemodel, :errors, :messages], :default => default_message) : default_message)
    end
	
    def self.helo_domain
        (ActionMailer::Base.default_url_options[:host] rescue nil) \
        || ENV['SERVER_ADDR']                                      \
        || 'localhost'
    end

end

require 'validates_email_format_of/active_model' if defined?(::ActiveModel) && !(ActiveModel::VERSION::MAJOR < 2 || (2 == ActiveModel::VERSION::MAJOR && ActiveModel::VERSION::MINOR < 1))
require 'validates_email_format_of/railtie' if defined?(::Rails)
