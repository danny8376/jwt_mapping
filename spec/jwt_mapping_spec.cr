require "./spec_helper"

class Test
  include JWT::Token
  property k1 : String
  property k2 : String

  def initialize
    @k1 = "v1"
    @k2 = "v2"
  end
end

describe JWT do
  describe "#encode" do
    it "encodes with HS256" do
      key = "SecretKey"
      token = Test.new.to_jwt(key, JWT::Algorithm::HS256)
      token.should eq "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
    end
  end

  describe "#decode" do
    it "decodes and verifies JWT" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = Test.from_jwt(token, "SecretKey", JWT::Algorithm::HS256)
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.k1.should eq("v1")
      payload.k2.should eq("v2")
    end

    it "decodes and verifies JWT with dynamic key" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = Test.from_jwt(token, algorithm: JWT::Algorithm::HS256) do |header, payload|
        "SecretKey"
      end
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.k1.should eq("v1")
      payload.k2.should eq("v2")
    end

    it "decodes and verifies JWT with dynamic key and auto algorithm" do
      token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJrMSI6InYxIiwiazIiOiJ2MiJ9.spzfy63YQSKdoM3av9HHvLtWzFjPd1hbch2g3T1-nu4"
      payload, header = Test.from_jwt(token) do |header, payload|
        "SecretKey"
      end
      header.should eq({"typ" => "JWT", "alg" => "HS256"})
      payload.k1.should eq("v1")
      payload.k2.should eq("v2")
    end
  end
end
