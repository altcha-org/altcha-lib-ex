defmodule AltchaTest do
  use ExUnit.Case, async: true

  # ---------------------------------------------------------------------------
  # V1 tests
  # ---------------------------------------------------------------------------

  defmodule V1Test do
    use ExUnit.Case, async: true

    alias Altcha.V1.Solution

    alias Altcha.V1.{
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
        assert Altcha.V1.hash_hex(data, :sha) == expected
      end

      test "hash/2 with sha256 algorithm" do
        data = "test"
        expected = :crypto.hash(:sha256, data) |> Base.encode16() |> String.downcase()
        assert Altcha.V1.hash_hex(data, :sha256) == expected
      end

      test "hash/2 with sha512 algorithm" do
        data = "test"
        expected = :crypto.hash(:sha512, data) |> Base.encode16() |> String.downcase()
        assert Altcha.V1.hash_hex(data, :sha512) == expected
      end

      test "hmac_hash/3 with sha1 algorithm" do
        data = "test"
        key = "key"
        expected = :crypto.mac(:hmac, :sha, key, data) |> Base.encode16() |> String.downcase()
        assert Altcha.V1.hmac_hex(data, :sha, key) == expected
      end

      test "hmac_hash/3 with sha256 algorithm" do
        data = "test"
        key = "key"
        expected = :crypto.mac(:hmac, :sha256, key, data) |> Base.encode16() |> String.downcase()
        assert Altcha.V1.hmac_hex(data, :sha256, key) == expected
      end

      test "hmac_hash/3 with sha512 algorithm" do
        data = "test"
        key = "key"
        expected = :crypto.mac(:hmac, :sha512, key, data) |> Base.encode16() |> String.downcase()
        assert Altcha.V1.hmac_hex(data, :sha512, key) == expected
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

        challenge = Altcha.V1.create_challenge(options)

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

        challenge = Altcha.V1.create_challenge(challenge_options)

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

        assert Altcha.V1.verify_solution(payload, @valid_hmac_key)
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

        refute Altcha.V1.verify_solution(invalid_payload, @valid_hmac_key)
      end

      test "returns false for invalid payload with salt splicing" do
        challenge_options = %ChallengeOptions{
          algorithm: :sha256,
          number: 123,
          salt_length: 16,
          hmac_key: @valid_hmac_key
        }

        challenge = Altcha.V1.create_challenge(challenge_options)

        payload =
          %Payload{
            algorithm: challenge.algorithm,
            challenge: challenge.challenge,
            number: 23,
            salt: challenge.salt <> "1",
            signature: challenge.signature
          }
          |> Payload.to_json()
          |> Base.encode64()

        refute Altcha.V1.verify_solution(payload, @valid_hmac_key)
      end
    end

    describe "verify_server_signature/2" do
      test "returns true for valid server signature" do
        payload =
          %ServerSignaturePayload{
            algorithm: "SHA-256",
            verification_data: "verified=true",
            signature:
              Altcha.V1.hmac_hex(Altcha.V1.hash("verified=true", :sha256), :sha256, @valid_hmac_key),
            verified: true
          }
          |> ServerSignaturePayload.to_json()
          |> Base.encode64()

        assert {true, _} = Altcha.V1.verify_server_signature(payload, @valid_hmac_key)
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

        assert {false, _} = Altcha.V1.verify_server_signature(invalid_payload, @valid_hmac_key)
      end
    end

    describe "verify_fields_hash/4" do
      test "verifies fields hash correctly" do
        form_data = %{"field1" => "value1", "field2" => "value2"}
        fields = ["field1", "field2"]
        fields_hash = Altcha.V1.hash_hex("value1\nvalue2", :sha256)

        assert Altcha.V1.verify_fields_hash(form_data, fields, fields_hash, :sha256)
      end

      test "returns false for incorrect fields hash" do
        form_data = %{"field1" => "value1", "field2" => "value2"}
        fields = ["field1", "field2"]
        fields_hash = "invalid_hash"

        refute Altcha.V1.verify_fields_hash(form_data, fields, fields_hash, :sha256)
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

        challenge = Altcha.V1.create_challenge(challenge_options)

        assert %Solution{
                 number: 123,
                 took: _took
               } =
                 Altcha.V1.solve_challenge(
                   challenge.challenge,
                   challenge.salt,
                   challenge.algorithm,
                   200
                 )
      end
    end
  end

  # ---------------------------------------------------------------------------
  # V2 tests
  # ---------------------------------------------------------------------------

  defmodule V2Test do
    use ExUnit.Case, async: true

    alias Altcha.V2
    alias Altcha.V2.{Challenge, ChallengeParameters, Solution, CreateChallengeOptions, SolveChallengeOptions, VerifySolutionOptions}

    @hmac_secret "test_secret"

    describe "canonical_json/1" do
      test "produces sorted camelCase JSON matching JS reference" do
        params = %ChallengeParameters{
          algorithm: "SHA-256",
          nonce: "aabbcc",
          salt: "ddeeff",
          cost: 5,
          key_length: 32,
          key_prefix: "00"
        }

        json = V2.canonical_json(params)
        decoded = Jason.decode!(json)

        assert Map.keys(decoded) == Enum.sort(Map.keys(decoded))
        assert decoded["algorithm"] == "SHA-256"
        assert decoded["nonce"] == "aabbcc"
        assert decoded["salt"] == "ddeeff"
        assert decoded["cost"] == 5
        assert decoded["keyLength"] == 32
        assert decoded["keyPrefix"] == "00"
        refute Map.has_key?(decoded, "keySignature")
        refute Map.has_key?(decoded, "memoryCost")
        refute Map.has_key?(decoded, "parallelism")
        refute Map.has_key?(decoded, "expiresAt")
      end

      test "includes optional fields when present" do
        params = %ChallengeParameters{
          algorithm: "PBKDF2/SHA-256",
          nonce: "nn",
          salt: "ss",
          cost: 100,
          key_length: 32,
          key_prefix: "0000",
          expires_at: 9999,
          memory_cost: 16384,
          parallelism: 1
        }

        json = V2.canonical_json(params)
        decoded = Jason.decode!(json)

        assert decoded["expiresAt"] == 9999
        assert decoded["memoryCost"] == 16384
        assert decoded["parallelism"] == 1
      end
    end

    describe "password_buffer/3" do
      test "uint32 mode appends counter as big-endian 4 bytes" do
        nonce = <<1, 2, 3, 4>>
        buf = V2.password_buffer(nonce, 1, :uint32)
        assert buf == <<1, 2, 3, 4, 0, 0, 0, 1>>
      end

      test "string mode appends counter as UTF-8 string" do
        nonce = <<1, 2, 3>>
        buf = V2.password_buffer(nonce, 42, :string)
        assert buf == <<1, 2, 3>> <> "42"
      end
    end

    describe "SHA algorithm" do
      test "derive_key produces deterministic output" do
        params = %ChallengeParameters{algorithm: "SHA-256", cost: 1, key_length: 32}
        salt = <<1, 2, 3, 4>>
        password = <<5, 6, 7, 8>>

        key1 = Altcha.V2.Algorithms.SHA.derive_key(params, salt, password)
        key2 = Altcha.V2.Algorithms.SHA.derive_key(params, salt, password)

        assert key1 == key2
        assert byte_size(key1) == 32
      end

      test "single iteration matches hash(salt ++ password)" do
        params = %ChallengeParameters{algorithm: "SHA-256", cost: 1, key_length: 32}
        salt = "mysalt"
        password = "mypassword"

        key = Altcha.V2.Algorithms.SHA.derive_key(params, salt, password)
        expected = :crypto.hash(:sha256, salt <> password)

        assert key == expected
      end

      test "multiple iterations chain hashes" do
        params = %ChallengeParameters{algorithm: "SHA-256", cost: 2, key_length: 32}
        salt = "s"
        password = "p"

        key = Altcha.V2.Algorithms.SHA.derive_key(params, salt, password)
        expected = :crypto.hash(:sha256, :crypto.hash(:sha256, salt <> password))

        assert key == expected
      end
    end

    describe "PBKDF2 algorithm" do
      test "derive_key produces deterministic output" do
        params = %ChallengeParameters{algorithm: "PBKDF2/SHA-256", cost: 1000, key_length: 32}
        salt = <<0, 1, 2, 3>>
        password = <<4, 5, 6, 7>>

        key1 = Altcha.V2.Algorithms.PBKDF2.derive_key(params, salt, password)
        key2 = Altcha.V2.Algorithms.PBKDF2.derive_key(params, salt, password)

        assert key1 == key2
        assert byte_size(key1) == 32
      end

      test "matches Erlang crypto.pbkdf2_hmac" do
        params = %ChallengeParameters{algorithm: "PBKDF2/SHA-256", cost: 1000, key_length: 32}
        salt = "salt"
        password = "password"

        key = Altcha.V2.Algorithms.PBKDF2.derive_key(params, salt, password)
        expected = :crypto.pbkdf2_hmac(:sha256, password, salt, 1000, 32)

        assert key == expected
      end
    end

    describe "create_challenge/1" do
      test "creates unsigned challenge without hmac_signature_secret" do
        options = %CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1
        }

        challenge = V2.create_challenge(options)

        assert %Challenge{} = challenge
        assert challenge.signature == nil
        assert challenge.parameters.algorithm == "SHA-256"
        assert challenge.parameters.cost == 1
        assert String.length(challenge.parameters.nonce) == 32
        assert String.length(challenge.parameters.salt) == 32
        assert challenge.parameters.key_prefix == "00"
      end

      test "creates signed challenge with hmac_signature_secret" do
        options = %CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        }

        challenge = V2.create_challenge(options)

        assert %Challenge{} = challenge
        assert is_binary(challenge.signature)
        assert String.length(challenge.signature) == 64
      end

      test "deterministic challenge with counter" do
        options = %CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          counter: 42,
          hmac_signature_secret: @hmac_secret
        }

        challenge = V2.create_challenge(options)

        assert is_binary(challenge.parameters.key_prefix)
        assert String.length(challenge.parameters.key_prefix) > 0
      end

      test "sets expiration" do
        expires = DateTime.to_unix(DateTime.utc_now(), :second) + 3600

        options = %CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          expires_at: expires
        }

        challenge = V2.create_challenge(options)
        assert challenge.parameters.expires_at == expires
      end
    end

    describe "solve_challenge/1" do
      test "solves SHA challenge" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        })

        solution =
          V2.solve_challenge(%SolveChallengeOptions{
            challenge: challenge,
            timeout: 30_000
          })

        assert %Solution{} = solution
        assert is_integer(solution.counter)
        assert is_binary(solution.derived_key)
        assert String.starts_with?(solution.derived_key, challenge.parameters.key_prefix)
      end

      test "solves PBKDF2 challenge" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "PBKDF2/SHA-256",
          cost: 1000,
          hmac_signature_secret: @hmac_secret
        })

        solution =
          V2.solve_challenge(%SolveChallengeOptions{
            challenge: challenge,
            timeout: 30_000
          })

        assert %Solution{} = solution
        assert String.starts_with?(solution.derived_key, challenge.parameters.key_prefix)
      end

      test "returns nil on timeout" do
        # Challenge with very long key prefix that won't be found quickly
        challenge = %Challenge{
          parameters: %ChallengeParameters{
            algorithm: "SHA-256",
            nonce: "aabb",
            salt: "ccdd",
            cost: 1,
            key_length: 32,
            key_prefix: "ffffffffffffffff"
          },
          signature: nil
        }

        result =
          V2.solve_challenge(%SolveChallengeOptions{
            challenge: challenge,
            timeout: 10
          })

        assert result == nil
      end
    end

    describe "verify_solution/1" do
      test "verifies valid solution end-to-end" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        })

        solution = V2.solve_challenge(%SolveChallengeOptions{challenge: challenge})

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: challenge,
            solution: solution,
            hmac_signature_secret: @hmac_secret
          })

        assert %V2.VerifySolutionResult{verified: true} = result
        assert result.expired == false
        assert result.invalid_signature == false
        assert result.invalid_solution == false
      end

      test "returns expired when challenge has passed expiration" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          expires_at: 1,
          hmac_signature_secret: @hmac_secret
        })

        solution = %Altcha.V2.Solution{counter: 0, derived_key: "00"}

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: challenge,
            solution: solution,
            hmac_signature_secret: @hmac_secret
          })

        assert result.expired == true
        assert result.verified == false
      end

      test "returns invalid_signature when challenge is unsigned" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1
        })

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: challenge,
            solution: %Altcha.V2.Solution{counter: 0, derived_key: "00"},
            hmac_signature_secret: @hmac_secret
          })

        assert result.invalid_signature == true
        assert result.verified == false
      end

      test "returns invalid_signature when signature is tampered" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        })

        tampered = %{challenge | signature: String.duplicate("0", 64)}

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: tampered,
            solution: %Altcha.V2.Solution{counter: 0, derived_key: "00"},
            hmac_signature_secret: @hmac_secret
          })

        assert result.invalid_signature == true
        assert result.verified == false
      end

      test "returns invalid_solution for wrong counter" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        })

        solution = V2.solve_challenge(%SolveChallengeOptions{challenge: challenge})

        wrong_solution = %{solution | counter: solution.counter + 999_999}

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: challenge,
            solution: wrong_solution,
            hmac_signature_secret: @hmac_secret
          })

        assert result.invalid_solution == true
        assert result.verified == false
      end

      test "verifies deterministic challenge with key_signature fast path" do
        options = %CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          counter: 7,
          hmac_signature_secret: @hmac_secret,
          hmac_key_signature_secret: "key_secret"
        }

        challenge = V2.create_challenge(options)
        assert challenge.parameters.key_signature != nil

        # Solve to get the derived key
        solution = V2.solve_challenge(%SolveChallengeOptions{challenge: challenge})
        assert solution.counter == 7

        result =
          V2.verify_solution(%VerifySolutionOptions{
            challenge: challenge,
            solution: solution,
            hmac_signature_secret: @hmac_secret,
            hmac_key_signature_secret: "key_secret"
          })

        assert result.verified == true
        assert result.invalid_solution == false
      end
    end

    describe "decode_payload/1" do
      test "decodes Base64-encoded JSON payload" do
        challenge = V2.create_challenge(%CreateChallengeOptions{
          algorithm: "SHA-256",
          cost: 1,
          hmac_signature_secret: @hmac_secret
        })

        solution = V2.solve_challenge(%SolveChallengeOptions{challenge: challenge})

        payload = %V2.Payload{challenge: challenge, solution: solution}
        encoded = payload |> Jason.encode!() |> Base.encode64()

        decoded = V2.decode_payload(encoded)

        assert %V2.Payload{} = decoded
        assert decoded.challenge.parameters.algorithm == "SHA-256"
        assert decoded.solution.counter == solution.counter
        assert decoded.solution.derived_key == solution.derived_key
      end
    end

    describe "verify_fields_hash/4" do
      test "verifies fields hash correctly" do
        form_data = %{"field1" => "value1", "field2" => "value2"}
        fields = ["field1", "field2"]
        fields_hash = :crypto.hash(:sha256, "value1\nvalue2") |> Base.encode16() |> String.downcase()

        assert V2.verify_fields_hash(form_data, fields, fields_hash, "SHA-256")
      end

      test "returns false for incorrect hash" do
        form_data = %{"field1" => "value1"}
        fields = ["field1"]

        refute V2.verify_fields_hash(form_data, fields, "badhash", "SHA-256")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Backward-compatibility: top-level Altcha module delegates to V1
  # ---------------------------------------------------------------------------

  defmodule BackwardCompatTest do
    use ExUnit.Case, async: true

    @valid_hmac_key "test_key"

    test "Altcha.create_challenge/1 delegates to V1" do
      options = %Altcha.V1.ChallengeOptions{
        algorithm: :sha256,
        number: 5,
        salt_length: 8,
        hmac_key: @valid_hmac_key
      }

      challenge = Altcha.create_challenge(options)
      assert challenge.algorithm == :sha256
    end

    test "Altcha.verify_solution/2 delegates to V1" do
      options = %Altcha.V1.ChallengeOptions{
        algorithm: :sha256,
        number: 5,
        salt_length: 8,
        hmac_key: @valid_hmac_key
      }

      challenge = Altcha.create_challenge(options)

      payload =
        %Altcha.V1.Payload{
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number: 5,
          salt: challenge.salt,
          signature: challenge.signature
        }
        |> Altcha.V1.Payload.to_json()
        |> Base.encode64()

      assert Altcha.verify_solution(payload, @valid_hmac_key)
    end
  end
end
