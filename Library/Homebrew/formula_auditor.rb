# typed: strict
# frozen_string_literal: true

require "deprecate_disable"
require "formula_versions"
require "formula_name_cask_token_auditor"
require "livecheck/livecheck"
require "resource_auditor"
require "utils"
require "utils/shared_audits"
require "utils/output"
require "utils/git"
require "style"
require "tap_auditor"

module Homebrew
  # Auditor for checking common violations in {Formula}e.
  class FormulaAuditor
    include FormulaCellarChecks
    include Utils::Curl
    include Utils::Output::Mixin

    sig { override.returns(Formula) }
    attr_reader :formula

    sig { returns(String) }
    attr_reader :text

    sig { returns(T::Array[T.any(String, T::Hash[Symbol, T.untyped])]) }
    attr_reader :problems

    sig { returns(T::Array[T.any(String, T::Hash[Symbol, T.untyped])]) }
    attr_reader :new_formula_problems

    sig {
      params(
        formula:             Formula,
        new_formula:         T.nilable(T::Boolean),
        strict:              T.nilable(T::Boolean),
        online:              T.nilable(T::Boolean),
        git:                 T.nilable(T::Boolean),
        display_cop_names:   T.nilable(T::Boolean),
        only:                T.nilable(T::Array[String]),
        except:              T.nilable(T::Array[String]),
        style_offenses:      T.nilable(T::Array[Style::Offense]),
        core_tap:            T.nilable(T::Boolean),
        tap_audit:           T.nilable(T::Boolean),
        spdx_license_data:   T.nilable(T::Hash[String, T.untyped]),
        spdx_exception_data: T.nilable(T::Hash[String, T.untyped]),
      ).void
    }
    def initialize(formula, new_formula: nil, strict: nil, online: nil, git: nil, display_cop_names: nil, only: nil,
                   except: nil, style_offenses: nil, core_tap: nil, tap_audit: nil, spdx_license_data: nil,
                   spdx_exception_data: nil)
      @formula = formula
      @versioned_formula = T.let(formula.versioned_formula?, T::Boolean)
      @new_formula_inclusive = new_formula
      @new_formula = new_formula && !@versioned_formula
      @strict = strict
      @online = online
      @git = git
      @display_cop_names = display_cop_names
      @only = only
      @except = except
      # Accept precomputed style offense results, for efficiency
      @style_offenses = style_offenses
      # Allow the formula tap to be set as homebrew/core, for testing purposes
      @core_tap = T.let(formula.tap&.core_tap? || core_tap || false, T::Boolean)
      @problems = T.let([], T::Array[T.any(String, T::Hash[Symbol, T.untyped])])
      @new_formula_problems = T.let([], T::Array[T.any(String, T::Hash[Symbol, T.untyped])])
      @text = T.let(formula.path.open("rb", &:read), String)
      @specs = T.let(%w[stable head].filter_map { |s| formula.send(s) }, T::Array[SoftwareSpec])
      @spdx_license_data = spdx_license_data
      @spdx_exception_data = spdx_exception_data
      @tap_audit = tap_audit
      @committed_version_info_cache = T.let({}, T::Hash[String, T.untyped])
    end

    sig { returns(T::Array[String]) }
    def self.aliases
      # core aliases + tap alias names + tap alias full name
      @aliases ||= T.let(Formula.aliases + Formula.tap_aliases, T.nilable(T::Array[String]))
    end

    PERMITTED_LICENSE_MISMATCHES = T.let({
      "AGPL-3.0" => ["AGPL-3.0-only", "AGPL-3.0-or-later"],
      "GPL-2.0"  => ["GPL-2.0-only",  "GPL-2.0-or-later"],
      "GPL-3.0"  => ["GPL-3.0-only",  "GPL-3.0-or-later"],
      "LGPL-2.1" => ["LGPL-2.1-only", "LGPL-2.1-or-later"],
      "LGPL-3.0" => ["LGPL-3.0-only", "LGPL-3.0-or-later"],
    }.freeze, T::Hash[String, T::Array[String]])

    # The following licenses are non-free/open based on multiple sources (e.g. Debian, Fedora, FSF, OSI, ...)
    INCOMPATIBLE_LICENSES = T.let([
      "Aladdin",    # https://www.gnu.org/licenses/license-list.html#Aladdin
      "CPOL-1.02",  # https://www.gnu.org/licenses/license-list.html#cpol
      "gSOAP-1.3b", # https://salsa.debian.org/ellert/gsoap/-/blob/HEAD/debian/copyright
      "JSON",       # https://wiki.debian.org/DFSGLicenses#JSON_evil_license
      "MS-LPL",     # https://github.com/spdx/license-list-XML/issues/1432#issuecomment-1077680709
      "OPL-1.0",    # https://wiki.debian.org/DFSGLicenses#Open_Publication_License_.28OPL.29_v1.0
    ].freeze, T::Array[String])
    INCOMPATIBLE_LICENSE_PREFIXES = T.let([
      "BUSL",     # https://spdx.org/licenses/BUSL-1.1.html#notes
      "CC-BY-NC", # https://people.debian.org/~bap/dfsg-faq.html#no_commercial
      "Elastic",  # https://www.elastic.co/licensing/elastic-license#Limitations
      "SSPL",     # https://fedoraproject.org/wiki/Licensing/SSPL#License_Notes
    ].freeze, T::Array[String])

    sig { void }
    def audit_homepage
      homepage = formula.homepage

      return if homepage.blank?

      return unless @online

      return if formula.tap&.audit_exception :cert_error_allowlist, formula.name, homepage

      return unless DevelopmentTools.curl_handles_most_https_certificates?

      # Skip gnu.org and nongnu.org audit on GitHub runners
      # See issue: https://github.com/Homebrew/homebrew-core/issues/206757
      github_runner = GitHub::Actions.env_set? && !ENV["GITHUB_ACTIONS_HOMEBREW_SELF_HOSTED"]
      return if homepage.match?(%r{^https?://www\.(?:non)?gnu\.org/.+}) && github_runner

      use_homebrew_curl = [:stable, :head].any? do |spec_name|
        next false unless (spec = formula.send(spec_name))

        spec.using == :homebrew_curl
      end

      if (http_content_problem = curl_check_http_content(
        homepage,
        SharedAudits::URL_TYPE_HOMEPAGE,
        user_agents:       [:browser, :default],
        check_content:     true,
        strict:            @strict || false,
        use_homebrew_curl:,
      ))
        problem http_content_problem
      end
    end

    sig { params(regex: Regexp).returns(T.nilable([String, String])) }
    def get_repo_data(regex)
      return unless @core_tap
      return unless @online

      _, user, repo = *regex.match(T.must(formula.stable).url) if formula.stable
      _, user, repo = *regex.match(formula.homepage) unless user
      _, user, repo = *regex.match(T.must(formula.head).url) if !user && formula.head
      return if !user || !repo

      repo.delete_suffix!(".git")

      [user, repo]
    end

    sig { override.params(output: T.nilable(String)).void }
    def problem_if_output(output)
      problem(output) if output
    end

    sig { void }
    def audit
      only_audits = @only
      except_audits = @except

      methods.map(&:to_s).grep(/^audit_/).each do |audit_method_name|
        name = audit_method_name.delete_prefix("audit_")
        next if only_audits&.exclude?(name)
        next if except_audits&.include?(name)

        send(audit_method_name)
      end
    end

    private

    sig { params(message: String, location: T.nilable(Homebrew::SourceLocation), corrected: T::Boolean).void }
    def problem(message, location: nil, corrected: false)
      @problems << ({ message:, location:, corrected: })
    end

    sig { params(message: String, location: T.nilable(Homebrew::SourceLocation), corrected: T::Boolean).void }
    def new_formula_problem(message, location: nil, corrected: false)
      @new_formula_problems << ({ message:, location:, corrected: })
    end

    sig { params(repo_owner: String).returns(T::Boolean) }
    def self_submission?(repo_owner)
      return false if repo_owner.blank?

      SharedAudits.self_submission_for_repo_owner?(repo_owner)
    end

    sig { params(formula: Formula).returns(T::Boolean) }
    def head_only?(formula)
      !!formula.head && formula.stable.nil?
    end

    sig { params(formula: Formula).returns(T::Boolean) }
    def linux_only_gcc_dep?(formula)
      odie "`#linux_only_gcc_dep?` works only on Linux!" if Homebrew::SimulateSystem.simulating_or_running_on_macos?
      return false if formula.deps.none? { |dep| dep.name == "gcc" && !dep.implicit? }

      variations = formula.to_hash_with_variations["variations"]
      # The formula has no variations, so all OS-version-arch triples depend on GCC.
      return false if variations.blank?

      MacOSVersion::SYMBOLS.keys.product(OnSystem::ARCH_OPTIONS).each do |os, arch|
        bottle_tag = Utils::Bottles::Tag.new(system: os, arch:)
        next unless bottle_tag.valid_combination?

        variation_dependencies = variations.dig(bottle_tag.to_sym, "dependencies")
        # This variation either:
        #   1. does not exist
        #   2. has no variation-specific dependencies
        # In either case, it matches Linux. We must check for `nil` because an empty
        # array indicates that this variation does not depend on GCC.
        return false if variation_dependencies.nil?
        # We found a non-Linux variation that depends on GCC.
        return false if variation_dependencies.include?("gcc")
      end

      true
    end

    sig { params(tap: Tap, only_names: T::Array[String]).returns(T::Array[Pathname]) }
    def changed_formulae_paths(tap, only_names: [].freeze)
      return [] unless tap.git?

      base_ref = git_audit_base_ref(tap)
      changed_paths = Utils.safe_popen_read(Utils::Git.git, "-C", tap.path, "diff", "--name-only", base_ref)
                           .lines
                           .filter_map do |line|
        relative_path = line.chomp
        next unless relative_path.end_with?(".rb")

        absolute_path = tap.path/relative_path
        next unless absolute_path.exist?
        next unless absolute_path.to_s.start_with?(tap.formula_dir.to_s)

        absolute_path
      end
      return changed_paths if only_names.blank?

      expected_paths = only_names.filter_map do |name|
        formula_name = name.to_s.delete_prefix("#{tap.name}/")
        formula_name = formula_name.delete_suffix(".rb")
        tap.formula_files_by_name[formula_name]&.expand_path
      end.map(&:to_s)

      changed_paths.select { |path| expected_paths.include?(path.expand_path.to_s) }
    end

    sig { params(formula: Formula).returns([T::Hash[Symbol, T.untyped], T::Hash[Symbol, T.untyped]]) }
    def committed_version_info(formula: @formula)
      empty_result = [{}, {}]
      return empty_result unless @git

      tap = formula.tap
      return empty_result unless tap # skip formula not from core or any taps
      return empty_result unless tap.git? # git log is required
      return empty_result if formula.stable.blank?

      if @committed_version_info_cache.key?(formula.full_name)
        return @committed_version_info_cache.fetch(formula.full_name)
      end

      previous_version_info = {}
      base_ref_version_info = {}

      current_version = formula.stable&.version
      current_revision = formula.revision

      fv = FormulaVersions.new(formula)
      fv.rev_list(git_audit_base_ref(tap)) do |revision, path|
        begin
          fv.formula_at_revision(revision, path) do |f|
            stable = f.stable
            next if stable.blank?

            previous_version_info[:version]  = stable.version
            previous_version_info[:checksum] = stable.checksum
            previous_version_info[:revision] = f.revision
            previous_version_info[:version_scheme] = f.version_scheme
            previous_version_info[:compatibility_version] = f.compatibility_version

            base_ref_version_info[:url] ||= stable.url
            base_ref_version_info[:version]  ||= previous_version_info[:version]
            base_ref_version_info[:checksum] ||= previous_version_info[:checksum]
            base_ref_version_info[:revision] ||= previous_version_info[:revision]
            base_ref_version_info[:version_scheme] ||= previous_version_info[:version_scheme]
            base_ref_version_info[:compatibility_version] ||= previous_version_info[:compatibility_version]
          end
        rescue MacOSVersion::Error, LegacyDSLError
          break
        end

        break if previous_version_info[:version]  && current_version  != previous_version_info[:version]
        break if previous_version_info[:revision] && current_revision != previous_version_info[:revision]
      end

      previous_version_info.compact!
      base_ref_version_info.compact!

      @committed_version_info_cache[formula.full_name] = [previous_version_info, base_ref_version_info]
    end

    sig { params(tap: Tap).returns(String) }
    def git_audit_base_ref(tap)
      @git_audit_base_ref_cache ||= T.let({}, T.nilable(T::Hash[Pathname, T.nilable(String)]))
      @git_audit_base_ref_cache[tap.path] ||= Utils.popen_read(Utils::Git.git, "-C", tap.path, "merge-base",
                                                               "origin/HEAD", "HEAD").chomp.presence
      @git_audit_base_ref_cache[tap.path] ||= "origin/HEAD"
    end
  end
end
