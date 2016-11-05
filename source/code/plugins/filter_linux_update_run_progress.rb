require "rexml/document"
require "cgi"
require 'json'

require_relative 'patch_management_lib'
require_relative 'oms_common'

module Fluent
  class LinuxUpdatesRunProgressFilter < Filter

    Fluent::Plugin.register_filter('filter_linux_update_run_progress', self)    

    def configure(conf)
      super
      @hostname = OMS::Common.get_hostname or "Unknown host"
      # do the usual configuration here
    end

    def start
      super
      # This is the first method to be called when it starts running
      # Use it to allocate resources, etc.
      # LinuxUpdates.log = @log
    end

    def shutdown
      super
      # This method is called when Fluentd is shutting down.
      # Use it to free up resources, etc.
    end

    def filter(tag, time, record)
      linuxUpdates = LinuxUpdates.new
      return linuxUpdates.process_update_run(record, tag, @hostname, time)
    end # filter
  end # class
end # module