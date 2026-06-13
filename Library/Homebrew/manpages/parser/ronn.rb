# typed: strict
# frozen_string_literal: true

require "kramdown/parser/kramdown"

module Homebrew
  module Manpages
    module Parser
      # Kramdown parser with compatibility for ronn variable syntax.
      class Ronn < ::Kramdown::Parser::Kramdown
        sig { params(source: String, options: T::Hash[Symbol, T.untyped]).void }
        def initialize(source, options)
          super
          @block_parsers = T.let(@block_parsers, T::Array[Symbol])
          @span_parsers = T.let(@span_parsers, T::Array[Symbol])
          # Disable HTML parsing and replace it with variable parsing.
          # Also disable table parsing too because it depends on HTML parsing
          # and existing command descriptions may get misinterpreted as tables.
          # Typographic symbols is disabled as it detects `--` as en-dash.
          @block_parsers.delete(:block_html)
          @block_parsers.delete(:table)
          @span_parsers.delete(:span_html)
          @span_parsers.delete(:typographic_syms)
          @span_parsers << :variable
        end

        # HTML-like tags denote variables instead, except <br>.
        VARIABLE_REGEX = /<([\w\-|]+)>/
        define_parser(:variable, VARIABLE_REGEX, "<")
      end
    end
  end
end
