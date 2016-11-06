 
require_relative 'security_baseline_lib'
require_relative 'oms_common' 

module Fluent
  class SecurityBaselineFilter < Filter

    Fluent::Plugin.register_filter('filter_security_baseline', self)

    # config_param works like other plugins
    config_param :time, default: 0

    def configure(conf)
        super
        # Do the usual configuration here
        @hostname = OMS::Common.get_hostname or "Unknown host"
    end

    def start
        super
        # This is the first method to be called when it starts running
        # Use it to allocate resources, etc.
        OMS::SecurityBaseline.log = @log
    end

    def shutdown
        super
        # This method is called when Fluentd is shutting down.
        # Use it to free up resources, etc.
    end

    def filter(tag, time, record)       
        security_baseline_blob, security_baseline_summary_blob = OMS::SecurityBaseline.transform_and_wrap(record, @hostname, time)
        Fluent::Engine.emit("oms.security_baseline_summary", time, security_baseline_summary_blob)	
        return security_baseline_blob
    end # filter
  end # class
end # module
