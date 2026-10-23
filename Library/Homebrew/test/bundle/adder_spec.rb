# typed: true
# frozen_string_literal: true

require "bundle"
require "bundle/adder"

RSpec.describe Homebrew::Bundle::Adder do
  let(:file) { mktmpdir/"Brewfile" }

  it "separates new entries from an existing entry without a trailing newline" do
    file.write 'npm "typescript"'

    described_class.add("eslint", type: :npm, global: false, file: file.to_s)

    expect(Homebrew::Bundle::Brewfile.read(file: file.to_s).entries.map(&:name)).to eq(%w[typescript eslint])
  end

  it "keeps new entries out of a trailing comment without a newline" do
    file.write "# npm tools"

    described_class.add("eslint", type: :npm, global: false, file: file.to_s)

    expect(Homebrew::Bundle::Brewfile.read(file: file.to_s).entries.map(&:name)).to eq(["eslint"])
  end

  it "does not add a leading blank line to an empty Brewfile" do
    file.write ""

    described_class.add("eslint", type: :npm, global: false, file: file.to_s)

    expect(file.read).to eq "npm \"eslint\"\n"
  end

  it "preserves existing trailing newlines" do
    file.write "npm \"typescript\"\n\n"

    described_class.add("eslint", type: :npm, global: false, file: file.to_s)

    expect(file.read).to eq "npm \"typescript\"\n\nnpm \"eslint\"\n"
  end
end
