# frozen_string_literal: true

require 'spec_helper'
require 'jwt/jws/token'

RSpec.describe JWT::JWS::Token do
  describe '.create' do
    subject(:result) { described_class.create(jws: jws) }

    context "when segment's size fit the expected number of three" do
      let(:jws) { 'eyJhbGciOiJIUzI1NiJ9.eyJuIjoiYSJ9.yBpN8B7Wp7bLQLMc9tlr' }

      it { is_expected.to be_an_instance_of(described_class) }
    end

    context "when segment's size is larger then three" do
      let(:jws) { 'eyJhbGc.iOiJIUzI1NiJ9.eyJuIjoiYSJ9.yBpN8B7Wp7b.LQLMc9tlr' }

      it { expect { result }.to raise_error JWT::FormatError, 'JWS should contains 3 segments.' }
    end

    context "when segment's size is smaller then three" do
      let(:jws) { 'eyJhbGc.iOiJIUzI1NiJ9' }

      it { expect { result }.to raise_error JWT::FormatError, 'JWS should contains 3 segments.' }
    end
  end

  describe '.valid?' do
    subject(:result) { described_class.create(jws: jws) }

    context 'when the count of `.` along with adjustment matches segments size' do
      let(:jws) { 'eyJhbGciOiJIUzI1NiJ9.eyJuIjoiYSJ9.yBpN8B7Wp7bLQLMc9tlr' }

      it { is_expected.to be_an_instance_of(described_class) }
    end

    context 'when the count of `.` along with adjustment does not match segments size' do
      let(:jws) { 'eyJhbGc.' }

      it { expect { result }.to raise_error JWT::FormatError, 'JWS should contains 3 segments.' }
    end
  end
end