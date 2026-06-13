# typed: strict
# frozen_string_literal: true

require "extend/os/mac/pkgconf"

module OS
  module Mac
    module Diagnostic
      class Volumes
        sig { void }
        def initialize
          @volumes = T.let(get_mounts, T::Array[String])
        end

        sig { params(path: T.nilable(::Pathname)).returns(Integer) }
        def index_of(path)
          vols = get_mounts path

          # no volume found
          return -1 if vols.empty?

          vol_index = @volumes.index(vols[0])
          # volume not found in volume list
          return -1 if vol_index.nil?

          vol_index
        end

        sig { params(path: T.nilable(::Pathname)).returns(T::Array[String]) }
        def get_mounts(path = nil)
          vols = []
          # get the volume of path, if path is nil returns all volumes

          args = %w[/bin/df -P]
          args << path.to_s if path

          Utils.popen_read(*args) do |io|
            io.each_line do |line|
              case line.chomp
                # regex matches: /dev/disk0s2   489562928 440803616  48247312    91%    /
              when /^.+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]{1,3}%\s+(.+)/
                vols << Regexp.last_match(1)
              end
            end
          end
          vols
        end
      end

      module Checks
        extend T::Helpers

        requires_ancestor { Homebrew::Diagnostic::Checks }

        sig { params(verbose: T::Boolean).void }
        def initialize(verbose: true)
          super
          @found = T.let([], T::Array[String])
        end

        sig { returns(T::Array[String]) }
        def supported_configuration_checks
          %w[
            check_for_unsupported_macos
          ].freeze
        end

        sig { returns(T::Array[String]) }
        def build_from_source_checks
          %w[
            check_for_installed_developer_tools
            check_xcode_up_to_date
            check_clt_up_to_date
          ].freeze
        end

        sig { returns(T.nilable(String)) }
        def check_for_non_prefixed_findutils
          findutils = ::Formula["findutils"]
          return unless findutils.any_version_installed?

          gnubin = %W[#{findutils.opt_libexec}/gnubin #{findutils.libexec}/gnubin]
          default_names = Tab.for_name("findutils").with? "default-names"
          return if !default_names && !paths.intersect?(gnubin)

          <<~EOS
            Putting non-prefixed findutils in your path can cause python builds to fail.
          EOS
        rescue FormulaUnavailableError
          nil
        end
      end
    end
  end
end

Homebrew::Diagnostic::Checks.prepend(OS::Mac::Diagnostic::Checks)
