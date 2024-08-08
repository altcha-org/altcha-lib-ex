defmodule AltchaTest do
  use ExUnit.Case, async: true

  alias Altcha.Solution

  alias Altcha.{
    Challenge,
    Payload,
    ServerSignaturePayload,
    ChallengeOptions
  }

  @valid_hmac_key "test_key"

  describe "hashing functions" do
    test "hash/2 with sha1 algorithm" do
      data = "test"
      expected = :crypto.hash(:sha, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hash_hex(data, :sha) == expected
    end

    test "hash/2 with sha256 algorithm" do
      data = "test"
      expected = :crypto.hash(:sha256, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hash_hex(data, :sha256) == expected
    end

    test "hash/2 with sha512 algorithm" do
      data = "test"
      expected = :crypto.hash(:sha512, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hash_hex(data, :sha512) == expected
    end

    test "hmac_hash/3 with sha1 algorithm" do
      data = "test"
      key = "key"
      expected = :crypto.mac(:hmac, :sha, key, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hmac_hex(data, :sha, key) == expected
    end

    test "hmac_hash/3 with sha256 algorithm" do
      data = "test"
      key = "key"
      expected = :crypto.mac(:hmac, :sha256, key, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hmac_hex(data, :sha256, key) == expected
    end

    test "hmac_hash/3 with sha512 algorithm" do
      data = "test"
      key = "key"
      expected = :crypto.mac(:hmac, :sha512, key, data) |> Base.encode16() |> String.downcase()
      assert Altcha.hmac_hex(data, :sha512, key) == expected
    end
  end

  describe "Challenge module" do
    test "to_json/1 serializes correctly" do
      challenge = %Challenge{
        algorithm: :sha256,
        challenge: "challenge",
        maxnumber: 1000,
        salt: "salt",
        signature: "signature"
      }

      expected_json =
        %{
          algorithm: "SHA-256",
          challenge: "challenge",
          maxnumber: 1000,
          salt: "salt",
          signature: "signature"
        }
        |> Jason.encode!()

      assert Challenge.to_json(challenge) == expected_json
    end
  end

  describe "Payload module" do
    test "to_json/1 serializes correctly" do
      payload = %Payload{
        algorithm: :sha256,
        challenge: "challenge",
        number: 42,
        salt: "salt",
        signature: "signature"
      }

      expected_json =
        %{
          algorithm: "SHA-256",
          challenge: "challenge",
          number: 42,
          salt: "salt",
          signature: "signature"
        }
        |> Jason.encode!()

      assert Payload.to_json(payload) == expected_json
    end

    test "from_json/1 deserializes correctly" do
      json =
        %{
          "algorithm" => "SHA-256",
          "challenge" => "challenge",
          "number" => 42,
          "salt" => "salt",
          "signature" => "signature"
        }
        |> Jason.encode!()

      payload = Payload.from_json(json)

      assert payload.algorithm == :sha256
      assert payload.challenge == "challenge"
      assert payload.number == 42
      assert payload.salt == "salt"
      assert payload.signature == "signature"
    end
  end

  describe "ServerSignaturePayload module" do
    test "to_json/1 serializes correctly" do
      payload = %ServerSignaturePayload{
        algorithm: :sha256,
        verification_data: "data",
        signature: "signature",
        verified: true
      }

      expected_json =
        %{
          algorithm: :sha256,
          verificationData: "data",
          signature: "signature",
          verified: true
        }
        |> Jason.encode!()

      assert ServerSignaturePayload.to_json(payload) == expected_json
    end

    test "from_json/1 deserializes correctly" do
      json =
        %{
          "algorithm" => "SHA-256",
          "verificationData" => "data",
          "signature" => "signature",
          "verified" => true
        }
        |> Jason.encode!()

      payload = ServerSignaturePayload.from_json(json)

      assert payload.algorithm == :sha256
      assert payload.verification_data == "data"
      assert payload.signature == "signature"
      assert payload.verified == true
    end
  end

  describe "Challenge creation" do
    test "create_challenge/1 generates challenge" do
      options = %ChallengeOptions{
        algorithm: :sha256,
        max_number: 1000,
        salt_length: 16,
        hmac_key: @valid_hmac_key,
        number: 123,
        expires: DateTime.to_unix(DateTime.utc_now(), :second) + 600
      }

      challenge = Altcha.create_challenge(options)

      assert %Challenge{
               algorithm: :sha256,
               challenge: _challenge,
               maxnumber: 1000,
               salt: _salt,
               signature: _signature
             } = challenge
    end
  end

  describe "verify_solution/3" do
    test "returns true for valid payload" do
      challenge_options = %ChallengeOptions{
        algorithm: :sha256,
        number: 123,
        salt_length: 16,
        hmac_key: @valid_hmac_key
      }

      challenge = Altcha.create_challenge(challenge_options)

      payload =
        %Payload{
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number: 123,
          salt: challenge.salt,
          signature: challenge.signature
        }
        |> Payload.to_json()
        |> Base.encode64()

      assert Altcha.verify_solution(payload, @valid_hmac_key)
    end

    test "returns false for invalid payload" do
      invalid_payload =
        %{
          "algorithm" => "SHA-256",
          "challenge" => "invalid_challenge",
          "number" => "123",
          "salt" => "invalid_salt",
          "signature" => "invalid_signature"
        }
        |> Jason.encode!()
        |> Base.encode64()

      refute Altcha.verify_solution(invalid_payload, @valid_hmac_key)
    end
  end

  describe "verify_server_signature/2" do
    test "returns true for valid server signature" do
      payload =
        %ServerSignaturePayload{
          algorithm: "SHA-256",
          verification_data: "verified=true",
          signature: Altcha.hmac_hex(Altcha.hash("verified=true", :sha256), :sha256, @valid_hmac_key),
          verified: true
        }
        |> ServerSignaturePayload.to_json()
        |> Base.encode64()

      assert { true, _ } = Altcha.verify_server_signature(payload, @valid_hmac_key)
    end

    test "returns false for invalid server signature" do
      invalid_payload =
        %{
          "algorithm" => "SHA-256",
          "verificationData" => "data",
          "signature" => "invalid_signature",
          "verified" => true
        }
        |> Jason.encode!()
        |> Base.encode64()

      assert { false, _ } = Altcha.verify_server_signature(invalid_payload, @valid_hmac_key)
    end
  end

  describe "verify_fields_hash/4" do
    test "verifies fields hash correctly" do
      form_data = %{"field1" => "value1", "field2" => "value2"}
      fields = ["field1", "field2"]
      fields_hash = Altcha.hash_hex("value1\nvalue2", :sha256)

      assert Altcha.verify_fields_hash(form_data, fields, fields_hash, :sha256)
    end

    test "returns false for incorrect fields hash" do
      form_data = %{"field1" => "value1", "field2" => "value2"}
      fields = ["field1", "field2"]
      fields_hash = "invalid_hash"

      refute Altcha.verify_fields_hash(form_data, fields, fields_hash, :sha256)
    end
  end

  describe "solve_challenge/5" do
    test "finds solution" do
      challenge_options = %ChallengeOptions{
        algorithm: :sha256,
        number: 123,
        salt_length: 16,
        hmac_key: @valid_hmac_key
      }

      challenge = Altcha.create_challenge(challenge_options)

      assert %Solution{
               number: 123,
               took: _took
             } =
               Altcha.solve_challenge(
                 challenge.challenge,
                 challenge.salt,
                 challenge.algorithm,
                 200
               )
    end
  end
end
