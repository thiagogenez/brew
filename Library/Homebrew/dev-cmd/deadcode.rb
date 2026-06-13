# typed: strict
# frozen_string_literal: true

require "abstract_command"

module Homebrew
  module DevCmd
    class Deadcode < AbstractCommand
      # Spoom's default excludes plus `test/` so that definitions only
      # referenced by their specs are still reported as dead. `--exclude` takes
      # all values at once and replaces Spoom's defaults, so the defaults are
      # repeated here alongside `test/`.
      EXCLUDES = %w[vendor/ sorbet/ tmp/ log/ node_modules/ test/].freeze

      # Definitions documented as part of the public or internal API, defined
      # with an `override` signature, or marked `# deadcode:keep`, are always
      # kept: Spoom cannot see their dynamic, subclass or cross-tap (e.g.
      # homebrew-core) callers. Use `# deadcode:keep` for definitions that are
      # only reached dynamically (e.g. via `send`) and so are not part of any
      # API but must not be removed.
      PERSIST_REGEX = /^\s*#\s*@api\s+(?:public|internal)\b|^\s*#\s*deadcode:keep\b|\boverride\b/

      cmd_args do
        description <<~EOS
          Find and remove dead code identified by Spoom. Test code is excluded
          from the analysis so that definitions only referenced by their tests
          are also treated as dead. Definitions documented with `# @api public`
          or `# @api internal`, defined with an `override` signature, or marked
          with a `# deadcode:keep` comment, are always kept.
        EOS
        switch "-n", "--dry-run",
               description: "List the dead code that would be removed without removing it."

        named_args :none
      end

      sig { override.void }
      def run
        Homebrew.install_bundler_gems!(groups: ["typecheck"])

        # Sorbet doesn't use bash privileged mode so we align EUID and UID here.
        Process::UID.change_privilege(Process.euid) if Process.euid != Process.uid

        HOMEBREW_LIBRARY_PATH.cd do
          locations = dead_code_locations
          if locations.empty?
            ohai "No dead code found!"
            return
          end

          kept, locations = locations.partition { |location| persisted?(location) }
          unless kept.empty?
            ohai "Keeping #{Utils.pluralize("definition", kept.count, include_count: true)} " \
                 "documented as `@api` or defined with `override`."
          end

          if locations.empty?
            ohai "No dead code left to remove."
            return
          end

          if args.dry_run?
            ohai "Dead code that would be removed:"
            locations.each { |location| puts "  #{location}" }
            return
          end

          remove(locations)
        end
      end

      private

      sig { returns(T::Array[String]) }
      def dead_code_locations
        spoom_exec = %w[bundle exec spoom deadcode --no-color --exclude] + EXCLUDES

        ohai "Searching for dead code with Spoom..."
        # Spoom exits non-zero when it finds candidates, so don't fail on that.
        # Candidates are printed to stderr, so merge it into the captured output.
        output = Utils.popen_read(*spoom_exec, err: :out)

        locations = output.lines.filter_map { |line| line[/\s(\S+:\d+:\d+-\d+:\d+)\s*$/, 1] }

        # Remove from the bottom of each file upwards so that removing one
        # location doesn't shift the line numbers of those still to be removed.
        locations.sort_by! do |location|
          file, line_column = location.split(":", 2)
          line, column = line_column.to_s.split(":", 2)
          [file.to_s, line.to_i, column.to_i]
        end
        locations.reverse!
        locations
      end

      sig { params(location: String).returns(T::Boolean) }
      def persisted?(location)
        file, line, = location.split(":", 3)
        start_line = line.to_i
        return false if file.nil? || start_line.zero?

        path = Pathname(file)
        return false unless path.file?

        lines = path.read.lines
        # Walk upwards from the line above the definition, collecting the
        # contiguous signature and documentation lines, stopping at the first
        # blank line (which separates it from any preceding definition).
        index = start_line - 2
        while index >= 0
          text = lines[index].to_s
          break if text.strip.empty?
          return true if text.match?(PERSIST_REGEX)

          index -= 1
        end
        false
      end

      sig { params(locations: T::Array[String]).void }
      def remove(locations)
        removed = 0
        skipped = []
        locations.each do |location|
          # Spoom fails on code it can't safely rewrite (e.g. methods wrapped in
          # `begin`/`rescue` or files it cannot parse). Capture its output so a
          # failure doesn't dump a backtrace, and skip that location instead.
          Utils.safe_popen_read("bundle", "exec", "spoom", "deadcode", "remove", location, err: :out)
          removed += 1
        rescue ErrorDuringExecution
          skipped << location
        end

        # Spoom writes a temporary `PATCH` file while computing diffs; clean up
        # any copy left behind by a removal that failed partway through.
        patch = HOMEBREW_LIBRARY_PATH/"PATCH"
        patch.unlink if patch.exist?

        ohai "Removed #{Utils.pluralize("dead code definition", removed, include_count: true)}."
        return if skipped.empty?

        opoo "Skipped #{Utils.pluralize("definition", skipped.count, include_count: true)} Spoom could not remove:"
        skipped.each { |location| puts "  #{location}" }
      end
    end
  end
end
