# typed: strict
# frozen_string_literal: true

require "cask/denylist"
require "cask/download"
require "cask/installer"
require "cask/quarantine"
require "digest"
require "livecheck/livecheck"
require "source_location"
require "system_command"
require "utils/backtrace"
require "formula_name_cask_token_auditor"
require "utils/curl"
require "utils/shared_audits"
require "utils/output"

module Cask
  # Audit a cask for various problems.
  class Audit
    include SystemCommand::Mixin
    include ::Utils::Curl
    include ::Utils::Output::Mixin

    Error = T.type_alias do
      {
        message:   T.nilable(String),
        location:  T.nilable(Homebrew::SourceLocation),
        corrected: T::Boolean,
      }
    end

    sig { returns(Cask) }
    attr_reader :cask

    sig { returns(T.nilable(Download)) }
    attr_reader :download

    sig {
      params(
        cask: ::Cask::Cask, download: T::Boolean, quarantine: T::Boolean,
        online: T.nilable(T::Boolean), strict: T.nilable(T::Boolean), signing: T.nilable(T::Boolean),
        new_cask: T.nilable(T::Boolean), only: T::Array[String], except: T::Array[String]
      ).void
    }
    def initialize(
      cask,
      download: false, quarantine: false,
      online: nil, strict: nil, signing: nil,
      new_cask: nil, only: [], except: []
    )
      # `new_cask` implies `online`, `strict` and `signing`
      online = new_cask if online.nil?
      strict = new_cask if strict.nil?
      signing = new_cask if signing.nil?

      # `online` and `signing` imply `download`
      download ||= online || signing

      @cask = cask
      @download = T.let(nil, T.nilable(Download))
      @download = Download.new(cask, quarantine:) if download
      @online = online
      @strict = strict
      @signing = signing
      @new_cask = new_cask
      @only = only
      @except = except
      @livecheck_result = T.let(nil, T.nilable(T.any(T::Boolean, Symbol)))
    end

    sig { returns(T::Boolean) }
    def new_cask? = !!@new_cask

    sig { returns(T::Boolean) }
    def online? =!!@online

    sig { returns(T::Boolean) }
    def signing? = !!@signing

    sig { returns(T::Boolean) }
    def strict? = !!@strict

    sig { returns(::Cask::Audit) }
    def run!
      only_audits = @only
      except_audits = @except

      private_methods.map(&:to_s).grep(/^audit_/).each do |audit_method_name|
        name = audit_method_name.delete_prefix("audit_")
        next if !only_audits.empty? && only_audits.exclude?(name)
        next if except_audits.include?(name)

        send(audit_method_name)
      end

      self
    rescue => e
      odebug e, ::Utils::Backtrace.clean(e)
      add_error "exception while auditing #{cask}: #{e.message}"
      self
    end

    sig { returns(T::Array[Error]) }
    def errors
      @errors ||= T.let([], T.nilable(T::Array[Error]))
    end

    sig { returns(T::Boolean) }
    def errors?
      errors.any?
    end

    sig { returns(T::Boolean) }
    def success?
      !errors?
    end

    sig {
      params(
        message:     T.nilable(String),
        location:    T.nilable(Homebrew::SourceLocation),
        strict_only: T::Boolean,
      ).void
    }
    def add_error(message, location: nil, strict_only: false)
      # Only raise non-critical audits if the user specified `--strict`.
      return if strict_only && !@strict

      errors << { message:, location:, corrected: false }
    end

    sig { returns(T.nilable(String)) }
    def result
      Formatter.error("failed") if errors?
    end

    sig { returns(T.nilable(String)) }
    def summary
      return if success?

      summary = ["audit for #{cask}: #{result}"]

      errors.each do |error|
        summary << " #{Formatter.error("-")} #{error[:message]}"
      end

      summary.join("\n")
    end

    private

    LIVECHECK_REFERENCE_URL = "https://docs.brew.sh/Cask-Cookbook#stanza-livecheck"
    private_constant :LIVECHECK_REFERENCE_URL

    SOURCEFORGE_OSDN_REFERENCE_URL = "https://docs.brew.sh/Cask-Cookbook#sourceforgeosdn-urls"
    private_constant :SOURCEFORGE_OSDN_REFERENCE_URL

    VERIFIED_URL_REFERENCE_URL = "https://docs.brew.sh/Cask-Cookbook#when-url-and-homepage-domains-differ-add-verified"
    private_constant :VERIFIED_URL_REFERENCE_URL

    sig { void }
    def audit_languages
      @cask.languages.each do |language|
        Locale.parse(language)
      rescue Locale::ParserError
        add_error "Locale '#{language}' is invalid."
      end
    end

    sig {
      params(
        include_manual_installers: T::Boolean,
        _block:                    T.nilable(T.proc.params(
          arg0: T::Array[T.any(Artifact::Installer, Artifact::Pkg, Artifact::Relocated)],
          arg1: Pathname,
        ).void),
      ).void
    }
    def extract_artifacts(include_manual_installers: false, &_block)
      return unless online?
      return if (download = self.download).nil?

      artifacts = cask.artifacts.select do |artifact|
        artifact.is_a?(Artifact::Pkg) ||
          artifact.is_a?(Artifact::App) ||
          artifact.is_a?(Artifact::Binary) ||
          (include_manual_installers &&
            artifact.is_a?(Artifact::Installer) &&
            artifact.manual_install &&
            [".app", ".pkg"].include?(artifact.path.extname.downcase))
      end

      if @artifacts_extracted && @tmpdir
        yield artifacts, @tmpdir if block_given?
        return
      end

      return if artifacts.empty?

      @tmpdir ||= T.let(Pathname(Dir.mktmpdir("cask-audit", HOMEBREW_TEMP)), T.nilable(Pathname))

      # Clean up tmp dir when @tmpdir object is destroyed
      ObjectSpace.define_finalizer(
        @tmpdir,
        proc { FileUtils.remove_entry(@tmpdir) },
      )

      ohai "Downloading and extracting artifacts"

      downloaded_path = download.fetch

      primary_container = UnpackStrategy.detect(downloaded_path, type: @cask.container&.type, merge_xattrs: true)
      return if primary_container.nil?

      # If the container has any dependencies we need to install them or unpacking will fail.
      if primary_container.dependencies.any?

        install_options = {
          show_header:          true,
          installed_on_request: false,
          verbose:              false,
        }.compact

        Homebrew::Install.perform_preinstall_checks_once
        formula_installers = primary_container.dependencies.filter_map do |dep|
          next unless dep.is_a?(Formula)
          next if dep.linked?

          FormulaInstaller.new(
            dep,
            **install_options,
          )
        end
        valid_formula_installers = Homebrew::Install.fetch_formulae(formula_installers)

        formula_installers.each do |fi|
          next unless valid_formula_installers.include?(fi)

          fi.install
          fi.finish
        end
      end

      # Extract the container to the temporary directory.
      primary_container.extract_nestedly(to: @tmpdir, basename: downloaded_path.basename, verbose: false)

      if (nested_container = @cask.container&.nested)
        FileUtils.chmod_R "+rw", @tmpdir/nested_container, force: true, verbose: false
        UnpackStrategy.detect(@tmpdir/nested_container, merge_xattrs: true)
                      .extract_nestedly(to: @tmpdir, verbose: false)
      end

      # Propagate quarantine attributes from the downloaded file to extracted contents.
      # This is necessary because some extraction tools (like 7zr) don't preserve xattrs.
      Quarantine.propagate(from: downloaded_path, to: @tmpdir) if Quarantine.detect(downloaded_path)

      # Process rename operations after extraction
      # Create a temporary installer to process renames in the audit directory
      temp_installer = Installer.new(@cask)
      temp_installer.process_rename_operations(target_dir: @tmpdir)

      # Set the flag to indicate that extraction has occurred.
      @artifacts_extracted = T.let(true, T.nilable(TrueClass))

      # Yield the artifacts and temp directory to the block if provided.
      yield artifacts, @tmpdir if block_given?
    end

    sig { returns(T.nilable(T.any(T::Boolean, Symbol))) }
    def audit_livecheck_version
      return @livecheck_result unless @livecheck_result.nil?
      return unless online?
      return unless cask.version

      odebug "Auditing livecheck version"

      referenced_cask, = Homebrew::Livecheck.resolve_livecheck_reference(cask)

      # Respect skip conditions for a referenced cask
      if referenced_cask
        skip_info = Homebrew::Livecheck::SkipConditions.referenced_skip_information(
          referenced_cask,
          Homebrew::Livecheck.package_or_resource_name(cask),
        )
      end

      # Respect cask skip conditions (e.g. deprecated, disabled, latest, unversioned)
      skip_info ||= Homebrew::Livecheck::SkipConditions.skip_information(cask)
      if skip_info.present?
        @livecheck_result = :skip
        return @livecheck_result
      end

      result = Homebrew::Livecheck.latest_version(
        cask,
        referenced_formula_or_cask: referenced_cask,
      )
      if result
        throttle = cask.livecheck.throttle
        throttle_days = cask.livecheck.throttle_days
        if referenced_cask
          throttle ||= referenced_cask.livecheck.throttle
          throttle_days ||= referenced_cask.livecheck.throttle_days
        end

        latest_version = (throttle || throttle_days) ? result[:latest_throttled] : result[:latest]
      end

      if latest_version && (cask.version.to_s == latest_version.to_s)
        @livecheck_result = :auto_detected
        return @livecheck_result
      end

      add_error "Version '#{cask.version}' differs from '#{latest_version}' retrieved by livecheck."

      @livecheck_result = false
    end

    sig { returns(T.nilable(MacOSVersion)) }
    def cask_sparkle_min_os
      return unless online?
      return unless cask.livecheck_defined?
      return if cask.livecheck.strategy != :sparkle

      # `Sparkle` strategy blocks that use the `items` argument (instead of
      # `item`) contain arbitrary logic that ignores/overrides the strategy's
      # sorting, so we can't identify which item would be first/newest here.
      return if cask.livecheck.strategy_block.present? &&
                cask.livecheck.strategy_block.parameters[0] == [:opt, :items]

      content = Homebrew::Livecheck::Strategy.page_content(cask.livecheck.url)[:content]
      return if content.blank?

      begin
        items = Homebrew::Livecheck::Strategy::Sparkle.sort_items(
          Homebrew::Livecheck::Strategy::Sparkle.filter_items(
            Homebrew::Livecheck::Strategy::Sparkle.items_from_content(content),
          ),
        )
      rescue
        return
      end
      return if items.blank?

      normalize_min_os(items[0]&.minimum_system_version)
    end

    sig { returns(T.nilable(MacOSVersion)) }
    def cask_bundle_min_os
      return unless online?

      min_os = T.let(nil, T.untyped)
      @staged_path ||= T.let(cask.staged_path, T.nilable(Pathname))

      extract_artifacts do |artifacts, tmpdir|
        artifacts.each do |artifact|
          next if artifact.is_a?(Artifact::Installer)

          artifact_path = artifact.is_a?(Artifact::Pkg) ? artifact.path : artifact.source
          path = tmpdir/artifact_path.relative_path_from(cask.staged_path)

          # Handle .pkg artifacts by expanding and checking Distribution file
          if artifact.is_a?(Artifact::Pkg)
            pkg_expanded_dir = tmpdir/"pkg-expanded"
            begin
              system_command!("pkgutil", args: ["--expand", path.to_s, pkg_expanded_dir.to_s])

              distribution_file = pkg_expanded_dir/"Distribution"
              if File.exist?(distribution_file)
                distribution_content = File.read(distribution_file)
                if (match = distribution_content.match(/<os-version\s+min="(?<version>[^"]+)"/))
                  min_os = match[:version]
                  break if min_os
                end
              end
            rescue
              break
            end
          end

          info_plist_paths = Dir.glob("#{path}/**/Contents/Info.plist")

          # Ensure the main `Info.plist` file is checked first, as this can
          # sometimes use the min_os version from a framework instead
          if info_plist_paths.delete("#{path}/Contents/Info.plist")
            info_plist_paths.insert(0, "#{path}/Contents/Info.plist")
          end

          info_plist_paths.each do |plist_path|
            next unless File.exist?(plist_path)

            plist = system_command!("plutil", args: ["-convert", "xml1", "-o", "-", plist_path]).plist
            min_os = plist["LSMinimumSystemVersion"].presence
            break if min_os

            # Get the app bundle path from the plist path
            app_bundle_path = Pathname(plist_path).dirname.dirname
            next unless (main_binary = get_plist_main_binary(app_bundle_path))
            next if !File.exist?(main_binary) || File.open(main_binary, "rb") { |f| f.read(2) == "#!" }

            macho = MachO.open(main_binary)
            min_os = case macho
            when MachO::MachOFile
              [
                macho[:LC_VERSION_MIN_MACOSX].first&.version_string,
                macho[:LC_BUILD_VERSION].first&.minos_string,
              ]
            when MachO::FatFile
              # Collect requirements by architecture
              arch_min_os = { arm: [], intel: [] }
              macho.machos.each do |slice|
                macos_reqs = [
                  slice[:LC_VERSION_MIN_MACOSX].first&.version_string,
                  slice[:LC_BUILD_VERSION].first&.minos_string,
                ]

                case slice.cputype
                when *Hardware::CPU::ARM_ARCHS
                  arch_min_os[:arm].concat(macos_reqs)
                when *Hardware::CPU::INTEL_ARCHS
                  arch_min_os[:intel].concat(macos_reqs)
                end
              end

              # Only use the requirements for the current architecture
              arch_min_os.fetch(Homebrew::SimulateSystem.current_arch, [])
            end.compact.max
            break if min_os
          end
          break if min_os
        end
      end

      normalize_min_os(min_os)
    end

    sig { params(min_os: T.nilable(T.any(String, MacOSVersion))).returns(T.nilable(MacOSVersion)) }
    def normalize_min_os(min_os)
      return if min_os.nil?
      return if min_os.is_a?(String) && min_os.blank?

      min_os = if min_os.is_a?(MacOSVersion)
        min_os.strip_patch
      else
        MacOSVersion.new(min_os).strip_patch
      end

      # Big Sur is sometimes identified as 10.16, so we override it to the
      # expected macOS version (11).
      min_os = MacOSVersion.new("11") if min_os == "10.16"

      min_os
    rescue MacOSVersion::Error
      nil
    end

    sig { params(path: Pathname).returns(T.nilable(String)) }
    def get_plist_main_binary(path)
      return unless online?

      plist_path = "#{path}/Contents/Info.plist"
      return unless File.exist?(plist_path)

      plist = system_command!("plutil", args: ["-convert", "xml1", "-o", "-", plist_path]).plist
      binary = plist["CFBundleExecutable"].presence
      return unless binary

      binary_path = "#{path}/Contents/MacOS/#{binary}"

      binary_path if File.exist?(binary_path) && File.executable?(binary_path)
    end

    sig {
      params(
        url_to_check: T.any(String, URL),
        url_type:     String,
        location:     T.nilable(Homebrew::SourceLocation),
        options:      T.untyped,
      ).void
    }
    def validate_url_for_https_availability(url_to_check, url_type, location: nil, **options)
      problem = curl_check_http_content(url_to_check.to_s, url_type, **options)
      exception = cask.tap&.audit_exception(:secure_connection_audit_skiplist, cask.token, url_to_check.to_s)

      if problem
        add_error problem, location: location unless exception
      elsif exception
        add_error "#{url_to_check} is in the secure connection audit skiplist but does not need to be skipped",
                  location:
      end
    end

    sig { params(regex: T.any(String, Regexp)).returns(T.nilable(T::Array[String])) }
    def get_repo_data(regex)
      return unless online?

      _, user, repo = *regex.match(cask.url.to_s)
      _, user, repo = *regex.match(cask.homepage) unless user
      return if !user || !repo

      repo.gsub!(/.git$/, "")

      [user, repo]
    end

    sig { params(repo_owner: String).returns(T::Boolean) }
    def self_submission?(repo_owner)
      return false if repo_owner.empty?

      SharedAudits.self_submission_for_repo_owner?(repo_owner)
    end

    sig {
      params(regex: T.any(String, Regexp), valid_formats_array: T::Array[T.any(String, Regexp)]).returns(T::Boolean)
    }
    def bad_url_format?(regex, valid_formats_array)
      return false unless cask.url.to_s.match?(regex)

      valid_formats_array.none? { |format| cask.url.to_s.match?(format) }
    end

    sig { returns(T::Boolean) }
    def bad_sourceforge_url?
      bad_url_format?(%r{((downloads|\.dl)\.|//)sourceforge},
                      [
                        %r{\Ahttps://sourceforge\.net/projects/[^/]+/files/latest/download\Z},
                        %r{\Ahttps://downloads\.sourceforge\.net/(?!(project|sourceforge)/)},
                      ])
    end

    sig { returns(T::Boolean) }
    def bad_osdn_url?
      T.must(domain).match?(%r{^(?:\w+\.)*osdn\.jp(?=/|$)})
    end

    sig { returns(T.nilable(String)) }
    def homepage
      URI(cask.homepage.to_s).host
    end

    sig { returns(T.nilable(String)) }
    def domain
      URI(cask.url.to_s).host
    end

    sig { returns(T::Boolean) }
    def url_match_homepage?
      host = cask.url.to_s
      host_uri = URI(host)
      host = if host.match?(/:\d/) && host_uri.port != 80
        "#{host_uri.host}:#{host_uri.port}"
      else
        host_uri.host
      end

      home = homepage
      return false if home.blank?

      home.downcase!
      if (split_host = T.must(host).split(".")).length >= 3
        host = T.must(split_host[-2..]).join(".")
      end
      if (split_home = home.split(".")).length >= 3
        home = T.must(split_home[-2..]).join(".")
      end
      host == home
    end

    sig { params(url: String).returns(String) }
    def strip_url_scheme(url)
      url.sub(%r{^[^:/]+://(www\.)?}, "")
    end

    sig { returns(T.nilable(String)) }
    def url_from_verified
      return unless (verified_url = T.must(cask.url).verified)

      strip_url_scheme(verified_url)
    end

    sig { returns(T::Boolean) }
    def verified_matches_url?
      url_domain, url_path = strip_url_scheme(cask.url.to_s).split("/", 2)
      verified_domain, verified_path = url_from_verified&.split("/", 2)

      domains_match = (url_domain == verified_domain) ||
                      (verified_domain && url_domain&.end_with?(".#{verified_domain}"))
      paths_match = !verified_path || url_path&.start_with?(verified_path)
      (domains_match && paths_match) || false
    end

    sig { returns(T::Boolean) }
    def verified_present?
      cask.url&.verified.present?
    end

    sig { returns(T::Boolean) }
    def file_url?
      URI(cask.url.to_s).scheme == "file"
    end

    sig { returns(Tap) }
    def core_tap
      @core_tap ||= T.let(CoreTap.instance, T.nilable(Tap))
    end

    sig { returns(T::Array[String]) }
    def core_formula_names
      core_tap.formula_names
    end

    sig { returns(Tap) }
    def core_cask_tap
      @core_cask_tap ||= T.let(CoreCaskTap.instance, T.nilable(Tap))
    end

    sig { returns(T::Array[String]) }
    def core_cask_tokens
      core_cask_tap.cask_tokens
    end

    sig { returns(String) }
    def core_formula_url
      formula_path = Formulary.core_path(cask.token)
                              .to_s
                              .delete_prefix(core_tap.path.to_s)
      "#{core_tap.default_remote}/blob/HEAD#{formula_path}"
    end
  end
end
