# typed: strict
# frozen_string_literal: true

require "utils/svn"

module Homebrew
  # Auditor for checking common violations in {Resource}s.
  class ResourceAuditor
    include Utils::Curl

    sig { returns(T.nilable(String)) }
    attr_reader :name

    sig { returns(T.nilable(Version)) }
    attr_reader :version

    sig { returns(T.nilable(Checksum)) }
    attr_reader :checksum

    sig { returns(T.nilable(String)) }
    attr_reader :url

    sig { returns(T::Array[String]) }
    attr_reader :mirrors

    sig { returns(T.nilable(T.any(T::Class[AbstractDownloadStrategy], Symbol))) }
    attr_reader :using

    sig { returns(T::Hash[Symbol, T.untyped]) }
    attr_reader :specs

    sig { returns(T.nilable(Resource::Owner)) }
    attr_reader :owner

    sig { returns(Symbol) }
    attr_reader :spec_name

    sig { returns(T::Array[String]) }
    attr_reader :problems

    sig {
      params(
        resource:          T.any(Resource, SoftwareSpec),
        spec_name:         Symbol,
        online:            T.nilable(T::Boolean),
        strict:            T.nilable(T::Boolean),
        only:              T.nilable(T::Array[String]),
        except:            T.nilable(T::Array[String]),
        core_tap:          T.nilable(T::Boolean),
        use_homebrew_curl: T::Boolean,
      ).void
    }
    def initialize(resource, spec_name, online: nil, strict: nil, only: nil, except: nil, core_tap: nil,
                   use_homebrew_curl: false)
      @name     = T.let(resource.name, T.nilable(String))
      @version  = T.let(resource.version, T.nilable(Version))
      @checksum = T.let(resource.checksum, T.nilable(Checksum))
      @url      = T.let(resource.url&.to_s, T.nilable(String))
      @mirrors  = T.let(resource.mirrors, T::Array[String])
      @using    = T.let(resource.using, T.nilable(T.any(T::Class[AbstractDownloadStrategy], Symbol)))
      @specs    = T.let(resource.specs, T::Hash[Symbol, T.untyped])
      @owner    = T.let(resource.owner, T.nilable(T.any(Cask::Cask, Resource::Owner)))
      @spec_name = T.let(spec_name, Symbol)
      @online    = online
      @strict    = strict
      @only      = only
      @except    = except
      @core_tap  = core_tap
      @use_homebrew_curl = use_homebrew_curl
      @problems = T.let([], T::Array[String])
    end

    sig { returns(ResourceAuditor) }
    def audit
      only_audits = @only
      except_audits = @except

      methods.map(&:to_s).grep(/^audit_/).each do |audit_method_name|
        name = audit_method_name.delete_prefix("audit_")
        next if only_audits&.exclude?(name)
        next if except_audits&.include?(name)

        send(audit_method_name)
      end

      self
    end

    sig { returns(T::Array[String]) }
    def self.curl_deps
      @curl_deps ||= T.let(begin
        ["curl"] + ::Formula["curl"].recursive_dependencies.map(&:name).uniq
      rescue FormulaUnavailableError
        []
      end, T.nilable(T::Array[String]))
    end

    sig { void }
    def audit_urls
      urls = [url.to_s] + mirrors

      curl_dep = self.class.curl_deps.include?(owner!.name)
      # Ideally `ca-certificates` would not be excluded here, but sourcing a HTTP mirror was tricky.
      # Instead, we have logic elsewhere to pass `--insecure` to curl when downloading the certs.
      # TODO: try remove the OS/env conditional
      if Homebrew::SimulateSystem.simulating_or_running_on_macos? && spec_name == :stable &&
         owner!.name != "ca-certificates" && curl_dep && !urls.find { |u| u.start_with?("http://") }
        problem "Should always include at least one HTTP mirror"
      end

      return unless @online

      urls.each do |url|
        next if !@strict && mirrors.include?(url)

        strategy = DownloadStrategyDetector.detect(url, using)
        if strategy <= CurlDownloadStrategy && !url.start_with?("file")

          raise HomebrewCurlDownloadStrategyError, url if
            strategy <= HomebrewCurlDownloadStrategy && !::Formula["curl"].any_version_installed?

          # Skip ftp.gnu.org audit, upstream has asked us to reduce load.
          # See issue: https://github.com/Homebrew/brew/issues/20456
          next if url.match?(%r{^https?://ftp\.gnu\.org/.+})

          # Skip https audit for curl dependencies
          if !curl_dep && (http_content_problem = curl_check_http_content(
            url,
            "source URL",
            specs:,
            use_homebrew_curl: @use_homebrew_curl,
          ))
            problem http_content_problem
          end
        elsif strategy <= GitDownloadStrategy
          attempts = 0
          remote_exists = T.let(false, T::Boolean)
          while !remote_exists && attempts < Homebrew::EnvConfig.curl_retries.to_i
            remote_exists = Utils::Git.remote_exists?(url)
            attempts += 1
          end
          problem "The URL #{url} is not a valid Git URL" unless remote_exists
        elsif strategy <= SubversionDownloadStrategy
          next unless Utils::Svn.available?

          problem "The URL #{url} is not a valid SVN URL" unless Utils::Svn.remote_exists? url
        end
      end
    end

    sig { params(text: String).void }
    def problem(text)
      @problems << text
    end

    private

    sig { returns(Resource::Owner) }
    def owner!
      owner || raise("ResourceAuditor owner is nil")
    end

    sig { returns(String) }
    def url!
      url || raise("ResourceAuditor URL is nil")
    end
  end
end
