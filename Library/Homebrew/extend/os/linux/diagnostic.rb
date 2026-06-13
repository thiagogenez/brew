# typed: strict
# frozen_string_literal: true

require "tempfile"
require "utils/shell"
require "hardware"
require "os/linux"
require "os/linux/glibc"
require "os/linux/kernel"
require "sandbox"

module OS
  module Linux
    module Diagnostic
      # Linux-specific diagnostic checks for Homebrew.
      module Checks
        extend T::Helpers

        requires_ancestor { Homebrew::Diagnostic::Checks }

        sig { returns(T::Array[String]) }
        def supported_configuration_checks
          %w[
            check_glibc_minimum_version
            check_kernel_minimum_version
            check_supported_architecture
          ].freeze
        end

        sig { returns(T.nilable(String)) }
        def check_tmpdir_executable
          f = Tempfile.new(%w[homebrew_check_tmpdir_executable .sh], HOMEBREW_TEMP)
          f.write "#!/bin/sh\n"
          f.chmod 0700
          f.close
          return if system T.must(f.path)

          <<~EOS
            The directory #{HOMEBREW_TEMP} does not permit executing
            programs. It is likely mounted as "noexec". Please set `$HOMEBREW_TEMP`
            in your #{Utils::Shell.profile} to a different directory, for example:
              export HOMEBREW_TEMP=~/tmp
              echo 'export HOMEBREW_TEMP=~/tmp' >> #{Utils::Shell.profile}
          EOS
        ensure
          f&.unlink
        end
      end
    end
  end
end

Homebrew::Diagnostic::Checks.prepend(OS::Linux::Diagnostic::Checks)
