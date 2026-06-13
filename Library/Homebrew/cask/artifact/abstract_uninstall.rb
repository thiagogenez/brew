# typed: strict
# frozen_string_literal: true

require "timeout"

require "utils/user"
require "cask/artifact/abstract_artifact"
require "cask/pkg"
require "cask/utils/trash"
require "extend/hash/keys"
require "system_command"

module Cask
  module Artifact
    # Abstract superclass for uninstall artifacts.
    class AbstractUninstall < AbstractArtifact
      include SystemCommand::Mixin

      ORDERED_DIRECTIVES = [
        :early_script,
        :launchctl,
        :quit,
        :signal,
        :login_item,
        :kext,
        :script,
        :pkgutil,
        :delete,
        :trash,
        :rmdir,
      ].freeze

      METADATA_KEYS = [
        :on_upgrade,
      ].freeze

      sig { params(cask: Cask, directives: DirectivesType).returns(AbstractUninstall) }
      def self.from_args(cask, **directives)
        new(cask, **directives)
      end

      sig { returns(T::Hash[Symbol, DirectivesType]) }
      attr_reader :directives

      sig { params(cask: Cask, directives: DirectivesType).void }
      def initialize(cask, **directives)
        directives.assert_valid_keys(*ORDERED_DIRECTIVES, *METADATA_KEYS)

        super
        directives[:signal] = Array(directives[:signal]).flatten.each_slice(2).to_a
        @directives = directives

        # This is already included when loading from the API.
        return if cask.loaded_from_api?
        return unless directives.key?(:kext)

        cask.caveats do
          T.bind(self, ::Cask::DSL::Caveats)
          kext
        end
      end

      sig { returns(T::Hash[Symbol, DirectivesType]) }
      def to_h
        directives.to_h
      end

      sig { override.returns(String) }
      def summarize
        to_h.flat_map { |key, val| Array(val).map { |v| "#{key.inspect} => #{v.inspect}" } }.join(", ")
      end

      sig { returns(T::Array[String]) }
      def bundle_ids_to_reopen
        @bundle_ids_to_reopen ||= T.let([], T.nilable(T::Array[String]))
      end

      private

      sig { params(options: DirectivesType).void }
      def dispatch_uninstall_directives(**options)
        ORDERED_DIRECTIVES.each do |directive_sym|
          dispatch_uninstall_directive(directive_sym, **options)
        end
      end

      sig { params(directive_sym: Symbol, options: T.anything).void }
      def dispatch_uninstall_directive(directive_sym, **options)
        return unless directives.key?(directive_sym)

        args = directives[directive_sym]

        send(:"uninstall_#{directive_sym}", *(args.is_a?(Hash) ? [args] : args), **options)
      end

      sig { returns(Symbol) }
      def stanza
        self.class.dsl_key
      end

      sig { params(bundle_id: String).returns(T::Array[[Integer, Integer, T.nilable(String)]]) }
      def running_processes(bundle_id)
        system_command!("/bin/launchctl", args: ["list"])
          .stdout.lines.drop(1)
          .map { |line| line.chomp.split("\t") }
          .map { |pid, state, id| [pid.to_i, state.to_i, id] }
          .select do |(pid, _, id)|
            pid.nonzero? && /\A(?:application\.)?#{Regexp.escape(bundle_id)}(?:\.\d+){0,2}\Z/.match?(id)
          end
      end

      sig { params(search: String).returns(T::Array[String]) }
      def find_launchctl_with_wildcard(search)
        regex = Regexp.escape(search).gsub("\\*", ".*")
        system_command!("/bin/launchctl", args: ["list"])
          .stdout.lines.drop(1) # skip stdout column headers
          .filter_map do |line|
            pid, _state, id = line.chomp.split(/\s+/)
            id if pid.to_i.nonzero? && T.must(id).match?(regex)
          end
      end

      sig { returns(String) }
      def automation_access_instructions
        navigation_path = if MacOS.version >= :ventura
          "System Settings → Privacy & Security"
        else
          "System Preferences → Security & Privacy → Privacy"
        end

        <<~EOS
          Enable Automation access for "Terminal → System Events" in:
            #{navigation_path} → Automation
          if you haven't already.
        EOS
      end

      sig { params(bundle_id: String).returns(T::Boolean) }
      def running?(bundle_id)
        script = <<~JAVASCRIPT
          'use strict';

          ObjC.import('stdlib')

          function run(argv) {
            try {
              var app = Application(argv[0])
              if (app.running()) {
                $.exit(0)
              }
            } catch (err) { }

            $.exit(1)
          }
        JAVASCRIPT

        system_command("osascript", args:         ["-l", "JavaScript", "-e", script, bundle_id],
                                    print_stderr: true).status.success? || false
      end

      sig { params(bundle_id: String).returns(SystemCommand::Result) }
      def quit(bundle_id)
        script = <<~JAVASCRIPT
          'use strict';

          ObjC.import('stdlib')

          function run(argv) {
            var app = Application(argv[0])

            try {
              app.quit()
            } catch (err) {
              if (app.running()) {
                $.exit(1)
              }
            }

            $.exit(0)
          }
        JAVASCRIPT

        system_command "osascript", args:         ["-l", "JavaScript", "-e", script, bundle_id],
                                    print_stderr: false
      end
      private :quit

      # :script must come before :pkgutil, :delete, or :trash so that the script file is not already deleted
      sig {
        params(
          directives:     DirectivesType,
          command:        T.class_of(SystemCommand),
          directive_name: Symbol,
          force:          T::Boolean,
          _kwargs:        T.anything,
        ).void
      }
      def uninstall_script(directives, command:, directive_name: :script, force: false, **_kwargs)
        # TODO: Create a common `Script` class to run this and Artifact::Installer.
        executable, script_arguments = self.class.read_script_arguments(directives,
                                                                        "uninstall",
                                                                        { must_succeed: true, sudo: false },
                                                                        { print_stdout: true },
                                                                        directive_name)

        ohai "Running uninstall script #{executable}"
        raise CaskInvalidError.new(cask, "#{stanza} :#{directive_name} without :executable.") if executable.nil?

        executable_path = staged_path_join_executable(executable)

        if (executable_path.absolute? && !executable_path.exist?) ||
           (!executable_path.absolute? && which(executable_path.to_s).nil?)
          message = "uninstall script #{executable} does not exist"
          raise CaskError, "#{message}." unless force

          opoo "#{message}; skipping."
          return
        end

        command.run(executable_path, **script_arguments)
        sleep 1
      end

      # This returns T::Enumerable[[Pathname, T::Array[Pathname]]] when called without a block,
      # but sorbet doesn't support overloads.
      sig {
        params(
          action: Symbol,
          paths:  T::Array[T.any(Pathname, String)],
          _block: T.nilable(T.proc.params(path: T.any(Pathname, String), resolved_paths: T::Array[Pathname]).void),
        ).returns(T.untyped)
      }
      def each_resolved_path(action, paths, &_block)
        return enum_for(:each_resolved_path, action, paths) unless block_given?

        paths.each do |path|
          resolved_path = Pathname.new(path.to_s.sub(%r{^~(?=(/|$))}, Dir.home))

          if resolved_path.relative?
            opoo "Skipping #{Formatter.identifier(action)} for relative path '#{path}'."
            next
          end

          if resolved_path.each_filename.any? { |part| [".", ".."].include?(part) }
            opoo "Skipping #{Formatter.identifier(action)} for path with relative segments '#{path}'."
            next
          end

          begin
            resolved_paths = Pathname.glob(resolved_path).reject do |target|
              next false unless undeletable?(target)

              opoo "Skipping #{Formatter.identifier(action)} for undeletable path '#{target}'."
              true
            end
            yield path, resolved_paths
          rescue Errno::EPERM
            raise if File.readable?(File.expand_path("~/Library/Application Support/com.apple.TCC"))

            navigation_path = if MacOS.version >= :ventura
              "System Settings → Privacy & Security"
            else
              "System Preferences → Security & Privacy → Privacy"
            end

            odie "Unable to remove some files. Please enable Full Disk Access for your terminal under " \
                 "#{navigation_path} → Full Disk Access."
          end
        end
      end

      sig {
        params(paths: Pathname, command: T.nilable(T.class_of(SystemCommand)), _kwargs: T.anything)
          .returns(T.nilable([T::Array[String], T::Array[String]]))
      }
      def trash_paths(*paths, command: nil, **_kwargs)
        return if paths.empty?

        trashed, untrashable = ::Cask::Utils::Trash.trash(*paths, command:)

        return trashed, untrashable if untrashable.empty?

        opoo "The following files could not be trashed, please do so manually:"
        $stderr.puts untrashable

        [trashed, untrashable]
      end

      sig { params(directories: Pathname, command: T.class_of(SystemCommand), _kwargs: T.anything).void }
      def recursive_rmdir(*directories, command:, **_kwargs)
        directories.all? do |resolved_path|
          puts resolved_path.sub(Dir.home, "~")

          if resolved_path.readable?
            children = resolved_path.children

            next false unless children.all? { |child| child.directory? || child.basename.to_s == ".DS_Store" }
          else
            lines = command.run!("/bin/ls", args: ["-A", "-F", "--", resolved_path], sudo: true, print_stderr: false)
                           .stdout.lines.map(&:chomp)
                           .flat_map(&:chomp)

            # Using `-F` above outputs directories ending with `/`.
            next false unless lines.all? { |l| l.end_with?("/") || l == ".DS_Store" }

            children = lines.map { |l| resolved_path/l.delete_suffix("/") }
          end

          # Directory counts as empty if it only contains a `.DS_Store`.
          if children.include?(ds_store = resolved_path/".DS_Store")
            Utils.gain_permissions_remove(ds_store, command:)
            children.delete(ds_store)
          end

          next false unless recursive_rmdir(*children, command:)

          begin
            Utils.gain_permissions_rmdir(resolved_path, command:)
          rescue Errno::ENOTEMPTY, ErrorDuringExecution
            next false
          end

          true
        end
      end

      sig { params(target: Pathname).returns(T::Boolean) }
      def undeletable?(target)
        !target.parent.writable?
      end
    end
  end
end

require "extend/os/cask/artifact/abstract_uninstall"
