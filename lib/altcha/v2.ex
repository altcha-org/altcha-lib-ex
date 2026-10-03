defmodule Altcha.V2 do
  @moduledoc """
  Altcha V2 module provides functions for creating and verifying ALTCHA v2 challenges.

  V2 uses key derivation functions (PBKDF2, iterative SHA) instead of simple hashing,
  allowing for tunable computational difficulty. The proof-of-work mechanism finds a
  counter value such that `deriveKey(nonce ++ counter, salt)` starts with a required
  hex prefix.

  ## Supported algorithms

  - `"SHA-256"`, `"SHA-384"`, `"SHA-512"` — iterative SHA hashing (built-in)
  - `"PBKDF2/SHA-256"`, `"PBKDF2/SHA-384"`, `"PBKDF2/SHA-512"` — PBKDF2 (built-in, OTP 24+)
  - Custom algorithms — pass a `derive_key_fn` option

  ## Basic usage

      options = %Altcha.V2.CreateChallengeOptions{
        algorithm: "PBKDF2/SHA-256",
        cost: 10_000,
        hmac_signature_secret: "my_secret"
      }
      challenge = Altcha.V2.create_challenge(options)

      # Verify a client-submitted payload
      payload = Altcha.V2.decode_payload(client_b64_string)
      result = Altcha.V2.verify_solution(%Altcha.V2.VerifySolutionOptions{
        challenge: payload.challenge,
        solution: payload.solution,
        hmac_signature_secret: "my_secret"
      })
  """

  @default_hmac_algorithm :sha256
  @default_key_length 32
  @default_key_prefix "00"
  @default_counter_mode :uint32
  # Number.MAX_SAFE_INTEGER: larger integers are not exact as JS numbers.
  @max_safe_integer 9_007_199_254_740_991

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  defmodule ChallengeParameters do
    @moduledoc """
    Parameters embedded in a V2 PoW challenge, signed with HMAC.
    All fields use camelCase when serialized to JSON to match the JS reference implementation.
    """
    @type t :: %__MODULE__{
            algorithm: String.t(),
            nonce: String.t(),
            salt: String.t(),
            cost: pos_integer(),
            key_length: pos_integer(),
            key_prefix: String.t(),
            key_signature: String.t() | nil,
            memory_cost: pos_integer() | nil,
            parallelism: pos_integer() | nil,
            expires_at: pos_integer() | nil,
            data: map() | nil
          }

    defstruct [
      :algorithm,
      :nonce,
      :salt,
      :cost,
      :key_length,
      :key_prefix,
      :key_signature,
      :memory_cost,
      :parallelism,
      :expires_at,
      :data
    ]

    defimpl Jason.Encoder do
      def encode(params, _opts) do
        Altcha.V2.parameters_to_map(params) |> Jason.encode!()
      end
    end
  end

  defmodule Challenge do
    @moduledoc """
    A V2 PoW challenge containing parameters and an optional HMAC signature.
    """
    @type t :: %__MODULE__{
            parameters: Altcha.V2.ChallengeParameters.t(),
            signature: String.t() | nil
          }

    defstruct [:parameters, :signature]

    defimpl Jason.Encoder do
      def encode(%{parameters: parameters, signature: signature}, _opts) do
        map = %{"parameters" => Altcha.V2.parameters_to_map(parameters)}

        map =
          if signature do
            Map.put(map, "signature", signature)
          else
            map
          end

        Jason.encode!(map)
      end
    end

    @doc """
    Converts a JSON string or map to a `Challenge` struct.
    """
    def from_json(json) when is_binary(json) do
      json |> Jason.decode!() |> from_map()
    end

    def from_map(%{"parameters" => params_map} = map) do
      %__MODULE__{
        parameters: Altcha.V2.ChallengeParameters |> struct(parse_params(params_map)),
        signature: map["signature"]
      }
    end

    defp parse_params(m) do
      %{
        algorithm: m["algorithm"],
        nonce: m["nonce"],
        salt: m["salt"],
        cost: m["cost"],
        key_length: m["keyLength"],
        key_prefix: m["keyPrefix"],
        key_signature: m["keySignature"],
        memory_cost: m["memoryCost"],
        parallelism: m["parallelism"],
        expires_at: m["expiresAt"],
        data: m["data"]
      }
    end
  end

  defmodule Solution do
    @moduledoc """
    A solution to a V2 PoW challenge.
    """
    @type t :: %__MODULE__{
            counter: non_neg_integer(),
            derived_key: String.t(),
            time: number() | nil
          }

    defstruct [:counter, :derived_key, :time]

    defimpl Jason.Encoder do
      def encode(%{counter: counter, derived_key: derived_key, time: time}, _opts) do
        map = %{"counter" => counter, "derivedKey" => derived_key}
        map = if time, do: Map.put(map, "time", time), else: map
        Jason.encode!(map)
      end
    end

    def from_map(m) do
      %__MODULE__{
        counter: m["counter"],
        derived_key: m["derivedKey"],
        time: m["time"]
      }
    end
  end

  defmodule Payload do
    @moduledoc """
    A client-submitted V2 payload containing the original challenge and the solution.
    Typically Base64-encoded JSON sent from the browser widget.
    """
    @type t :: %__MODULE__{
            challenge: Altcha.V2.Challenge.t(),
            solution: Altcha.V2.Solution.t()
          }

    defstruct [:challenge, :solution]

    defimpl Jason.Encoder do
      def encode(%{challenge: challenge, solution: solution}, _opts) do
        %{"challenge" => challenge, "solution" => solution} |> Jason.encode!()
      end
    end

    def from_json(json) when is_binary(json) do
      json |> Jason.decode!() |> from_map()
    end

    def from_map(%{"challenge" => challenge_map, "solution" => solution_map}) do
      %__MODULE__{
        challenge: Altcha.V2.Challenge.from_map(challenge_map),
        solution: Altcha.V2.Solution.from_map(solution_map)
      }
    end
  end

  defmodule VerifySolutionResult do
    @moduledoc """
    Result of verifying a V2 solution.
    """
    @type t :: %__MODULE__{
            expired: boolean(),
            invalid_signature: boolean() | nil,
            invalid_solution: boolean() | nil,
            time: number(),
            verified: boolean()
          }

    defstruct [:expired, :invalid_signature, :invalid_solution, :time, :verified]
  end

  defmodule ServerSignaturePayload do
    @moduledoc """
    A server-signed verification payload issued by the Altcha verification service.
    """
    @type t :: %__MODULE__{
            algorithm: String.t(),
            api_key: String.t() | nil,
            id: String.t() | nil,
            signature: String.t(),
            verification_data: String.t(),
            verified: boolean()
          }

    defstruct [:algorithm, :api_key, :id, :signature, :verification_data, :verified]

    def from_map(%{} = map) do
      %__MODULE__{
        algorithm: map["algorithm"],
        api_key: map["apiKey"],
        id: map["id"],
        signature: map["signature"],
        verification_data: map["verificationData"],
        verified: map["verified"] == true
      }
    end

    def from_json(json) when is_binary(json) do
      json |> Jason.decode!() |> from_map()
    end
  end

  defmodule CreateChallengeOptions do
    @moduledoc """
    Options for `Altcha.V2.create_challenge/1`.
    """
    defstruct [
      # Required: key derivation algorithm string (e.g. "PBKDF2/SHA-256", "SHA-256")
      :algorithm,
      # Required: computational cost (iterations / time cost)
      :cost,
      # Optional: known counter for deterministic challenge generation
      :counter,
      # Optional: counter encoding mode (:uint32 | :string), default :uint32
      :counter_mode,
      # Optional: metadata map, signed with the challenge. As in the JS reference, keep it
      # flat (string / number / boolean / nil values): maps nested inside lists are signed
      # with sorted keys, whereas JS keeps their original key order.
      :data,
      # Optional: custom derive_key_fn(params, salt_bytes, password_bytes) -> key_bytes
      :derive_key_fn,
      # Optional: expiration as Unix timestamp (integer) or DateTime
      :expires_at,
      # Optional: HMAC algorithm atom for signing (:sha256 | :sha384 | :sha512)
      :hmac_algorithm,
      # Optional: HMAC secret for signing the derived key (deterministic mode)
      :hmac_key_signature_secret,
      # Optional: HMAC secret for signing challenge parameters
      :hmac_signature_secret,
      # Optional: derived key length in bytes, default 32
      :key_length,
      # Optional: required hex prefix for the derived key, default "00"; lowercased.
      # A non-hex prefix raises ArgumentError.
      :key_prefix,
      # Optional: number of prefix bytes used in deterministic mode, default and maximum
      # key_length/2
      :key_prefix_length,
      # Optional: memory cost in KiB (Scrypt/Argon2id)
      :memory_cost,
      # Optional: parallelism factor (Scrypt/Argon2id)
      :parallelism
    ]
  end

  defmodule SolveChallengeOptions do
    @moduledoc """
    Options for `Altcha.V2.solve_challenge/1`.
    """
    defstruct [
      # Required: the challenge to solve
      :challenge,
      # Optional: counter encoding mode (:uint32 | :string), default :uint32
      :counter_mode,
      # Optional: starting counter value, default 0
      :counter_start,
      # Optional: counter increment per step, default 1
      :counter_step,
      # Optional: custom derive_key_fn(params, salt_bytes, password_bytes) -> key_bytes
      :derive_key_fn,
      # Optional: timeout in milliseconds, default 90_000; 0 or :infinity disables it
      :timeout
    ]
  end

  defmodule VerifySolutionOptions do
    @moduledoc """
    Options for `Altcha.V2.verify_solution/1`.
    """
    defstruct [
      # Required: the original challenge
      :challenge,
      # Optional: counter encoding mode (:uint32 | :string), default :uint32
      :counter_mode,
      # Optional: custom derive_key_fn(params, salt_bytes, password_bytes) -> key_bytes
      :derive_key_fn,
      # Optional: HMAC algorithm atom, default :sha256
      :hmac_algorithm,
      # Optional: HMAC secret for verifying the derived key signature
      :hmac_key_signature_secret,
      # Required: HMAC secret used when the challenge was created
      :hmac_signature_secret,
      # Required: the solution submitted by the client
      :solution
    ]
  end

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Creates a new V2 PoW challenge.

  Generates a random nonce and salt, computes the challenge parameters,
  and optionally signs them with HMAC using `hmac_signature_secret`.

  ## Options

  See `Altcha.V2.CreateChallengeOptions` for all available options.

  ## Examples

      challenge = Altcha.V2.create_challenge(%Altcha.V2.CreateChallengeOptions{
        algorithm: "PBKDF2/SHA-256",
        cost: 10_000,
        hmac_signature_secret: "my_secret"
      })
  """
  def create_challenge(%CreateChallengeOptions{} = options) do
    algorithm = options.algorithm
    cost = options.cost
    key_length = options.key_length || @default_key_length
    key_prefix = String.downcase(options.key_prefix || @default_key_prefix)

    if not hex?(key_prefix) do
      raise ArgumentError, "key_prefix must be a hex string, got: #{inspect(options.key_prefix)}"
    end

    # Capped so that deterministic mode always leaves half the key unrevealed.
    max_key_prefix_length = div(key_length, 2)

    key_prefix_length =
      min(options.key_prefix_length || max_key_prefix_length, max_key_prefix_length)

    counter_mode = options.counter_mode || @default_counter_mode

    nonce = :crypto.strong_rand_bytes(16) |> Base.encode16() |> String.downcase()
    salt = :crypto.strong_rand_bytes(16) |> Base.encode16() |> String.downcase()

    expires_at = normalize_expires_at(options.expires_at)

    parameters = %ChallengeParameters{
      algorithm: algorithm,
      nonce: nonce,
      salt: salt,
      cost: cost,
      key_length: key_length,
      key_prefix: key_prefix,
      memory_cost: options.memory_cost,
      parallelism: options.parallelism,
      expires_at: expires_at,
      data: options.data
    }

    derive_fn = options.derive_key_fn || default_derive_key_fn(algorithm)

    {parameters, derived_key} =
      if options.counter != nil do
        nonce_bytes = Base.decode16!(nonce, case: :mixed)
        salt_bytes = Base.decode16!(salt, case: :mixed)
        password = password_buffer(nonce_bytes, options.counter, counter_mode)
        derived_key = derive_fn.(parameters, salt_bytes, password)

        prefix_hex =
          derived_key |> binary_part(0, key_prefix_length) |> Base.encode16(case: :lower)

        {%{parameters | key_prefix: prefix_hex}, derived_key}
      else
        {parameters, nil}
      end

    hmac_algorithm = options.hmac_algorithm || @default_hmac_algorithm

    if not present?(options.hmac_signature_secret) do
      %Challenge{parameters: parameters}
    else
      sign_challenge(
        hmac_algorithm,
        parameters,
        derived_key,
        options.hmac_signature_secret,
        options.hmac_key_signature_secret
      )
    end
  end

  @doc """
  Solves a V2 challenge by brute-forcing counter values until the derived key
  starts with the required prefix.

  Returns a `%Altcha.V2.Solution{}` on success, or `nil` if timed out or the challenge's
  `key_prefix` is not hex (no derived key can match it).

  ## Options

  See `Altcha.V2.SolveChallengeOptions` for all available options.
  """
  def solve_challenge(%SolveChallengeOptions{} = options) do
    # key_prefix is always lowercase hex; the key is matched case-insensitively.
    key_prefix = String.downcase(options.challenge.parameters.key_prefix)

    if hex?(key_prefix), do: solve_challenge(options, key_prefix), else: nil
  end

  defp solve_challenge(options, key_prefix) do
    challenge = options.challenge
    counter_start = options.counter_start || 0
    counter_step = options.counter_step || 1
    counter_mode = options.counter_mode || @default_counter_mode
    timeout = options.timeout || 90_000

    %{nonce: nonce, salt: salt} = challenge.parameters
    nonce_bytes = Base.decode16!(nonce, case: :mixed)
    salt_bytes = Base.decode16!(salt, case: :mixed)

    derive_fn = options.derive_key_fn || default_derive_key_fn(challenge.parameters.algorithm)

    key_prefix_bytes =
      if rem(String.length(key_prefix), 2) == 0 do
        Base.decode16!(key_prefix, case: :lower)
      else
        nil
      end

    start_time = System.monotonic_time(:millisecond)

    # Like JS, a zero timeout means no timeout.
    deadline = if timeout in [0, :infinity], do: :infinity, else: start_time + timeout

    Stream.iterate(counter_start, &(&1 + counter_step))
    |> Enum.reduce_while(nil, fn counter, _acc ->
      if deadline != :infinity and System.monotonic_time(:millisecond) > deadline do
        {:halt, nil}
      else
        password = password_buffer(nonce_bytes, counter, counter_mode)
        derived_key = derive_fn.(challenge.parameters, salt_bytes, password)

        if key_matches?(derived_key, key_prefix_bytes, key_prefix) do
          {:halt,
           %Solution{
             counter: counter,
             derived_key: Base.encode16(derived_key, case: :lower),
             time: System.monotonic_time(:millisecond) - start_time
           }}
        else
          {:cont, nil}
        end
      end
    end)
  end

  @doc """
  Verifies a client-submitted V2 solution against the original challenge.

  Performs the following checks in order:
  1. Whether the challenge has expired
  2. Whether the challenge has a signature
  3. Whether the challenge signature is valid (tamper protection)
  4. Whether the solution is valid (via key signature or re-derivation)

  Returns a `%Altcha.V2.VerifySolutionResult{}`. Raises `ArgumentError` when
  `hmac_signature_secret` is missing or empty, like the JS reference, whose Web Crypto
  HMAC rejects zero-length keys.

  ## Options

  See `Altcha.V2.VerifySolutionOptions` for all available options.
  """
  def verify_solution(%VerifySolutionOptions{} = options) do
    require_secret!(options.hmac_signature_secret, "hmac_signature_secret")

    challenge = options.challenge
    solution = options.solution
    hmac_algorithm = options.hmac_algorithm || @default_hmac_algorithm
    start_time = System.monotonic_time(:millisecond)

    cond do
      is_expired?(challenge.parameters) ->
        %VerifySolutionResult{
          expired: true,
          invalid_signature: nil,
          invalid_solution: nil,
          time: elapsed(start_time),
          verified: false
        }

      is_nil(challenge.signature) ->
        %VerifySolutionResult{
          expired: false,
          invalid_signature: true,
          invalid_solution: nil,
          time: elapsed(start_time),
          verified: false
        }

      not signature_valid?(
        hmac_algorithm,
        challenge.parameters,
        challenge.signature,
        options.hmac_signature_secret
      ) ->
        %VerifySolutionResult{
          expired: false,
          invalid_signature: true,
          invalid_solution: nil,
          time: elapsed(start_time),
          verified: false
        }

      true ->
        verify_solution_key(options, challenge, solution, hmac_algorithm, start_time)
    end
  end

  @doc """
  Decodes a Base64-encoded JSON payload from a client into a `%Altcha.V2.Payload{}`.

  Returns `nil` when the payload is missing or malformed.
  """
  def decode_payload(encoded) when is_binary(encoded) do
    json =
      case Base.decode64(encoded) do
        {:ok, decoded} -> decoded
        :error -> encoded
      end

    Payload.from_json(json)
  rescue
    _ -> nil
  end

  def decode_payload(_), do: nil

  @doc """
  Verifies if the hash of form fields matches the provided hash.
  """
  def verify_fields_hash(form_data, fields, fields_hash, algorithm \\ "SHA-256") do
    lines = Enum.map(fields, &(Map.get(form_data, &1, "") |> to_string()))
    joined = Enum.join(lines, "\n")
    digest = sha_digest(algorithm)
    computed = :crypto.hash(digest, joined) |> Base.encode16() |> String.downcase()
    constant_time_equal?(computed, fields_hash)
  end

  @doc """
  Verifies a server signature payload issued by the Altcha verification service.

  Accepts a `%Altcha.V2.ServerSignaturePayload{}` struct, a plain map with string
  keys, a raw JSON string, or a Base64-encoded JSON string.

  Returns `{%VerifySolutionResult{}, verification_data | nil}` where
  `verification_data` is a map of typed values parsed from the URL-encoded
  `verificationData` query string.

  The `VerifySolutionResult` fields:
  - `expired` — `expire` timestamp in the verification data has passed
  - `invalid_signature` — HMAC of `hash(verificationData)` does not match
  - `invalid_solution` — `verified` is not `true` in the data or payload

  Raises `ArgumentError` when `hmac_secret` is missing or empty, like the JS reference.
  A missing or malformed payload is a failed verification with `nil` verification data.
  """
  def verify_server_signature(payload, hmac_secret) do
    require_secret!(hmac_secret, "hmac_secret")
    start_time = System.monotonic_time(:millisecond)

    case to_server_signature_payload(payload) do
      %ServerSignaturePayload{verification_data: data} = payload when is_binary(data) ->
        do_verify_server_signature(payload, hmac_secret, start_time)

      _ ->
        result = %VerifySolutionResult{
          expired: false,
          invalid_signature: true,
          invalid_solution: true,
          time: elapsed(start_time),
          verified: false
        }

        {result, nil}
    end
  end

  defp do_verify_server_signature(payload, hmac_secret, start_time) do
    digest = sha_digest(payload.algorithm)
    hash_data = :crypto.hash(digest, payload.verification_data)
    expected_signature = do_hmac_hex(hash_data, digest, hmac_secret)

    verification_data = parse_verification_data(payload.verification_data)

    expired = is_map(verification_data) and server_signature_expired?(verification_data["expire"])

    invalid_signature = not constant_time_equal?(payload.signature, expected_signature)

    invalid_solution =
      not is_map(verification_data) or
        verification_data["verified"] != true or
        payload.verified != true

    verified = not expired and not invalid_signature and not invalid_solution

    result = %VerifySolutionResult{
      expired: expired,
      invalid_signature: invalid_signature,
      invalid_solution: invalid_solution,
      time: elapsed(start_time),
      verified: verified
    }

    {result, verification_data}
  end

  # The payload is client-controlled: anything that is not a JSON object yields nil.
  defp to_server_signature_payload(%ServerSignaturePayload{} = payload), do: payload
  defp to_server_signature_payload(%{} = map), do: ServerSignaturePayload.from_map(map)

  defp to_server_signature_payload(binary) when is_binary(binary) do
    json =
      case Base.decode64(binary) do
        {:ok, decoded} -> decoded
        :error -> binary
      end

    case Jason.decode(json) do
      {:ok, %{} = map} -> ServerSignaturePayload.from_map(map)
      _ -> nil
    end
  end

  defp to_server_signature_payload(_), do: nil

  # ---------------------------------------------------------------------------
  # Internal helpers (exposed for testing)
  # ---------------------------------------------------------------------------

  # Counters follow JS number semantics, since the widget's JSON counter is a JS number:
  # uint32 mode applies ToUint32 (truncate, wrap modulo 2^32), string mode applies
  # Number#toString. A JSON `7.0`, which Jason decodes as a float, thus behaves as 7.
  @doc false
  def password_buffer(nonce_bytes, counter, :uint32)
      when is_integer(counter) and abs(counter) <= @max_safe_integer do
    nonce_bytes <> <<counter::32-big>>
  end

  def password_buffer(nonce_bytes, counter, :uint32) when is_integer(counter) do
    case js_double(counter) do
      # ToUint32(Infinity) is 0.
      :infinity -> nonce_bytes <> <<0::32>>
      double -> password_buffer(nonce_bytes, double, :uint32)
    end
  end

  def password_buffer(nonce_bytes, counter, :uint32) when is_float(counter) do
    nonce_bytes <> <<trunc(counter)::32-big>>
  end

  def password_buffer(nonce_bytes, counter, :string) when is_number(counter) do
    nonce_bytes <> encode_js_number(counter)
  end

  @doc false
  def canonical_json(%ChallengeParameters{} = params) do
    # Keys must be sorted alphabetically and use camelCase (matching JS reference):
    # algorithm, cost, data, expiresAt, keyLength, keyPrefix, keySignature, memoryCost,
    # nonce, parallelism, salt
    [
      {"algorithm", params.algorithm},
      {"cost", params.cost},
      {"data", params.data},
      {"expiresAt", params.expires_at},
      {"keyLength", params.key_length},
      {"keyPrefix", params.key_prefix},
      {"keySignature", params.key_signature},
      {"memoryCost", params.memory_cost},
      {"nonce", params.nonce},
      {"parallelism", params.parallelism},
      {"salt", params.salt}
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> encode_canonical_object()
    |> IO.iodata_to_binary()
  end

  @doc false
  def parameters_to_map(%ChallengeParameters{} = params) do
    %{
      "algorithm" => params.algorithm,
      "cost" => params.cost,
      "keyLength" => params.key_length,
      "keyPrefix" => params.key_prefix,
      "nonce" => params.nonce,
      "salt" => params.salt
    }
    |> maybe_put("data", params.data)
    |> maybe_put("expiresAt", params.expires_at)
    |> maybe_put("keySignature", params.key_signature)
    |> maybe_put("memoryCost", params.memory_cost)
    |> maybe_put("parallelism", params.parallelism)
  end

  # ---------------------------------------------------------------------------
  # Private
  # ---------------------------------------------------------------------------

  defp sign_challenge(
         hmac_algorithm,
         parameters,
         derived_key,
         hmac_signature_secret,
         hmac_key_signature_secret
       ) do
    parameters =
      if derived_key && present?(hmac_key_signature_secret) do
        key_sig = do_hmac_hex(derived_key, hmac_algorithm, hmac_key_signature_secret)
        %{parameters | key_signature: key_sig}
      else
        parameters
      end

    canonical = canonical_json(parameters)
    signature = do_hmac_hex(canonical, hmac_algorithm, hmac_signature_secret)

    %Challenge{parameters: parameters, signature: signature}
  end

  defp signature_valid?(hmac_algorithm, parameters, signature, hmac_secret) do
    expected = do_hmac_hex(canonical_json(parameters), hmac_algorithm, hmac_secret)
    constant_time_equal?(signature, expected)
  end

  defp verify_solution_key(options, challenge, solution, hmac_algorithm, start_time) do
    if present?(challenge.parameters.key_signature) and
         present?(options.hmac_key_signature_secret) do
      # Fast path: verify HMAC of the derived key. `derivedKey` is client-controlled;
      # anything that is not valid hex is a clean invalid solution, not an exception.
      valid =
        case decode_derived_key(solution.derived_key) do
          {:ok, derived_key_bytes} ->
            expected_key_sig =
              do_hmac_hex(derived_key_bytes, hmac_algorithm, options.hmac_key_signature_secret)

            constant_time_equal?(challenge.parameters.key_signature, expected_key_sig)

          :error ->
            false
        end

      %VerifySolutionResult{
        expired: false,
        invalid_signature: false,
        invalid_solution: !valid,
        time: elapsed(start_time),
        verified: valid
      }
    else
      if is_number(solution.counter) do
        verify_rederived_key(options, challenge, solution, start_time)
      else
        # A non-numeric counter cannot match; JS would coerce it, but the widget only
        # ever sends numbers.
        %VerifySolutionResult{
          expired: false,
          invalid_signature: false,
          invalid_solution: true,
          time: elapsed(start_time),
          verified: false
        }
      end
    end
  end

  defp verify_rederived_key(options, challenge, solution, start_time) do
    # Re-derive the key from the solution counter and compare
    counter_mode = options.counter_mode || @default_counter_mode
    derive_fn = options.derive_key_fn || default_derive_key_fn(challenge.parameters.algorithm)

    nonce_bytes = Base.decode16!(challenge.parameters.nonce, case: :mixed)
    salt_bytes = Base.decode16!(challenge.parameters.salt, case: :mixed)
    password = password_buffer(nonce_bytes, solution.counter, counter_mode)

    expected_key = derive_fn.(challenge.parameters, salt_bytes, password)
    expected_key_hex = Base.encode16(expected_key, case: :lower)
    key_matches = constant_time_equal?(expected_key_hex, solution.derived_key)

    # key_prefix is always lowercase hex; the key is matched case-insensitively.
    prefix_matches =
      String.starts_with?(expected_key_hex, String.downcase(challenge.parameters.key_prefix))

    valid = key_matches and prefix_matches

    %VerifySolutionResult{
      expired: false,
      invalid_signature: false,
      invalid_solution: !valid,
      time: elapsed(start_time),
      verified: valid
    }
  end

  defp decode_derived_key(hex) when is_binary(hex), do: Base.decode16(hex, case: :mixed)
  defp decode_derived_key(_), do: :error

  defp key_matches?(derived_key, nil, key_prefix) do
    Base.encode16(derived_key, case: :lower) |> String.starts_with?(key_prefix)
  end

  defp key_matches?(derived_key, key_prefix_bytes, _key_prefix) do
    prefix_len = byte_size(key_prefix_bytes)

    byte_size(derived_key) >= prefix_len and
      binary_part(derived_key, 0, prefix_len) == key_prefix_bytes
  end

  # Canonical JSON must be byte-identical to the JS reference,
  # `JSON.stringify(sortKeys(parameters))`, so that signatures verify across
  # implementations and after the widget re-serializes the challenge.
  defp encode_canonical_object(fields) do
    entries =
      Enum.map(fields, fn {k, v} -> [encode_js_string(k), ?:, encode_canonical_value(v)] end)

    [?{, Enum.intersperse(entries, ?,), ?}]
  end

  defp encode_canonical_value(nil), do: "null"
  defp encode_canonical_value(true), do: "true"
  defp encode_canonical_value(false), do: "false"
  defp encode_canonical_value(v) when is_atom(v), do: encode_js_string(Atom.to_string(v))
  defp encode_canonical_value(v) when is_binary(v), do: encode_js_string(v)
  defp encode_canonical_value(v) when is_number(v), do: encode_js_number(v)

  defp encode_canonical_value(v) when is_list(v),
    do: [?[, Enum.intersperse(Enum.map(v, &encode_canonical_value/1), ?,), ?]]

  defp encode_canonical_value(v) when is_map(v) and not is_struct(v) do
    v
    |> Enum.map(fn {k, value} -> {to_string(k), value} end)
    |> Enum.sort_by(fn {k, _} -> js_key_order(k) end)
    |> encode_canonical_object()
  end

  # Structs (e.g. DateTime) serialize through their Jason.Encoder implementation.
  defp encode_canonical_value(v), do: Jason.encode!(v)

  # JSON.stringify emits array-index keys ("0".."4294967294" in canonical form) first, in
  # numeric order, then the other keys in insertion order, which sortKeys made UTF-16
  # code-unit order. Big-endian UTF-16 bytes compare in code-unit order.
  defp js_key_order(key) do
    case Integer.parse(key) do
      {index, ""} when index in 0..4_294_967_294//1 ->
        if Integer.to_string(index) == key, do: {0, index}, else: {1, utf16_key(key)}

      _ ->
        {1, utf16_key(key)}
    end
  end

  defp utf16_key(key), do: :unicode.characters_to_binary(key, :utf8, :utf16)

  # JSON.stringify string escaping: quote, backslash, and control characters only, with
  # lowercase \u00xx escapes. UTF-8 continuation bytes are >= 0x80, so scanning bytes is safe.
  defp encode_js_string(string) do
    [?", for(<<byte <- string>>, into: "", do: escape_js_byte(byte)), ?"]
  end

  defp escape_js_byte(?"), do: "\\\""
  defp escape_js_byte(?\\), do: "\\\\"
  defp escape_js_byte(?\b), do: "\\b"
  defp escape_js_byte(?\f), do: "\\f"
  defp escape_js_byte(?\n), do: "\\n"
  defp escape_js_byte(?\r), do: "\\r"
  defp escape_js_byte(?\t), do: "\\t"
  defp escape_js_byte(byte) when byte < 0x20, do: "\\u00" <> Base.encode16(<<byte>>, case: :lower)
  defp escape_js_byte(byte), do: <<byte>>

  # JS numbers are doubles: integers beyond 2^53 become the nearest double, and integers
  # beyond the double range become Infinity, which JSON.stringify writes as null.
  defp encode_js_number(n) when is_integer(n) and abs(n) <= @max_safe_integer,
    do: Integer.to_string(n)

  defp encode_js_number(n) when is_integer(n) do
    case js_double(n) do
      :infinity -> "null"
      double -> encode_js_number(double)
    end
  end

  # -0.0 prints as "0" in JS.
  defp encode_js_number(f) when f == 0, do: "0"
  defp encode_js_number(f) when f < 0, do: "-" <> encode_js_number(-f)

  # ECMA-262 Number::toString(x) for x > 0, over the shortest round-trip digits.
  defp encode_js_number(f) do
    {digits, point} = shortest_decimal(f)
    k = byte_size(digits)

    cond do
      k <= point and point <= 21 ->
        digits <> String.duplicate("0", point - k)

      0 < point and point <= 21 ->
        binary_part(digits, 0, point) <> "." <> binary_part(digits, point, k - point)

      -6 < point and point <= 0 ->
        "0." <> String.duplicate("0", -point) <> digits

      true ->
        exponent = point - 1
        sign = if exponent < 0, do: "-", else: "+"

        mantissa =
          if k == 1,
            do: digits,
            else: binary_part(digits, 0, 1) <> "." <> binary_part(digits, 1, k - 1)

        mantissa <> "e" <> sign <> Integer.to_string(abs(exponent))
    end
  end

  # The double JSON.parse produces for an integer: parsing the decimal rounds to nearest,
  # whereas :erlang.float/1 truncates. Beyond the double range JS yields Infinity.
  defp js_double(n) when is_integer(n) do
    String.to_float(Integer.to_string(n) <> ".0")
  rescue
    ArgumentError -> :infinity
  end

  # Shortest round-trip digits of a positive float as {digits, point}, where
  # f = 0.<digits> × 10^point and digits has no leading or trailing zeros.
  defp shortest_decimal(f) do
    {mantissa, exponent} =
      case String.split(:erlang.float_to_binary(f, [:short]), "e") do
        [mantissa] -> {mantissa, 0}
        [mantissa, exponent] -> {mantissa, String.to_integer(exponent)}
      end

    [int, frac] = String.split(mantissa, ".")
    all_digits = int <> frac
    digits = String.trim_leading(all_digits, "0")
    point = byte_size(int) + exponent - (byte_size(all_digits) - byte_size(digits))

    {String.trim_trailing(digits, "0"), point}
  end

  defp do_hmac_hex(data, :sha256, key),
    do: :crypto.mac(:hmac, :sha256, key, data) |> Base.encode16() |> String.downcase()

  defp do_hmac_hex(data, :sha384, key),
    do: :crypto.mac(:hmac, :sha384, key, data) |> Base.encode16() |> String.downcase()

  defp do_hmac_hex(data, :sha512, key),
    do: :crypto.mac(:hmac, :sha512, key, data) |> Base.encode16() |> String.downcase()

  # Client-supplied values (signature, derivedKey) may be any JSON type; a non-string
  # never matches.
  defp constant_time_equal?(a, b) when not (is_binary(a) and is_binary(b)), do: false
  defp constant_time_equal?(a, b) when byte_size(a) != byte_size(b), do: false

  defp constant_time_equal?(a, b) do
    import Bitwise

    :binary.bin_to_list(a)
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc -> acc ||| bxor(x, y) end)
    |> Kernel.==(0)
  end

  # Same rule as the JS reference (`expiresAt && expiresAt < Date.now() / 1000`): the
  # current time keeps its fractional seconds, and a nil or zero expires_at never expires.
  defp is_expired?(%ChallengeParameters{expires_at: nil}), do: false
  defp is_expired?(%ChallengeParameters{expires_at: expires_at}) when expires_at == 0, do: false

  defp is_expired?(%ChallengeParameters{expires_at: expires_at}) do
    expires_at < System.os_time(:millisecond) / 1000
  end

  # Same rule as the JS reference (`expire && expire < Math.floor(Date.now() / 1000)`):
  # unlike challenge expiry, the current time is floored to whole seconds; a missing or
  # zero expire never expires.
  defp server_signature_expired?(expire) when is_number(expire) and expire != 0,
    do: expire < System.os_time(:second)

  defp server_signature_expired?(_), do: false

  defp elapsed(start_time), do: System.monotonic_time(:millisecond) - start_time

  # Secrets and keySignature follow JS truthiness: nil and "" both mean unset.
  defp present?(value), do: value not in [nil, ""]

  defp hex?(string), do: String.match?(string, ~r/\A[0-9a-f]*\z/)

  # A configuration error, not a verification outcome: raise instead of failing the
  # signature check with an empty key, which Erlang accepts but Web Crypto rejects.
  defp require_secret!(secret, name) do
    if not (is_binary(secret) and secret != "") do
      raise ArgumentError, "#{name} must be a non-empty string, got: #{inspect(secret)}"
    end
  end

  defp normalize_expires_at(nil), do: nil
  defp normalize_expires_at(%DateTime{} = dt), do: DateTime.to_unix(dt, :second)
  defp normalize_expires_at(n) when is_integer(n), do: n

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp default_derive_key_fn(algorithm) do
    cond do
      String.starts_with?(algorithm, "PBKDF2") ->
        &Altcha.V2.Algorithms.PBKDF2.derive_key/3

      String.starts_with?(algorithm, "SHA") ->
        &Altcha.V2.Algorithms.SHA.derive_key/3

      true ->
        raise ArgumentError,
              "No built-in support for algorithm #{inspect(algorithm)}. " <>
                "Pass a custom :derive_key_fn in the options."
    end
  end

  defp sha_digest("SHA-512"), do: :sha512
  defp sha_digest("SHA-384"), do: :sha384
  defp sha_digest(_), do: :sha256

  # Parses a URL-encoded verification data query string into a typed map.
  # Mirrors the JS v2 parseVerificationData function:
  # - "true"/"false" → boolean
  # - digit-only strings → integer
  # - decimal strings → float
  # - "fields" and "reasons" → list (comma-split)
  # - everything else → trimmed string
  defp parse_verification_data(data) do
    convert_to_list = ["fields", "reasons"]

    URI.decode_query(data)
    |> Map.new(fn {k, v} ->
      value =
        cond do
          v == "true" -> true
          v == "false" -> false
          # \A…\z, not ^…$: `$` would also match before a trailing newline.
          Regex.match?(~r/\A\d+\z/, v) -> String.to_integer(v)
          Regex.match?(~r/\A\d+\.\d+\z/, v) -> String.to_float(v)
          k in convert_to_list and v != "" -> v |> String.trim() |> String.split(",")
          true -> String.trim(v)
        end

      {k, value}
    end)
  rescue
    _ -> nil
  end
end
