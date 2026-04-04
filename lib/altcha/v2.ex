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
      # Optional: arbitrary metadata map
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
      # Optional: required hex prefix for the derived key, default "00"
      :key_prefix,
      # Optional: number of prefix bytes used in deterministic mode, default key_length/2
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
      # Optional: timeout in milliseconds, default 90_000
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
    key_prefix = options.key_prefix || @default_key_prefix
    key_prefix_length = options.key_prefix_length || div(key_length, 2)
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

        prefix_hex = derived_key |> binary_part(0, key_prefix_length) |> Base.encode16(case: :lower)

        {%{parameters | key_prefix: prefix_hex}, derived_key}
      else
        {parameters, nil}
      end

    hmac_algorithm = options.hmac_algorithm || @default_hmac_algorithm

    if options.hmac_signature_secret == nil do
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

  Returns a `%Altcha.V2.Solution{}` on success, or `nil` if timed out.

  ## Options

  See `Altcha.V2.SolveChallengeOptions` for all available options.
  """
  def solve_challenge(%SolveChallengeOptions{} = options) do
    challenge = options.challenge
    counter_start = options.counter_start || 0
    counter_step = options.counter_step || 1
    counter_mode = options.counter_mode || @default_counter_mode
    timeout_ms = options.timeout || 90_000

    %{nonce: nonce, salt: salt, key_prefix: key_prefix} = challenge.parameters
    nonce_bytes = Base.decode16!(nonce, case: :mixed)
    salt_bytes = Base.decode16!(salt, case: :mixed)

    derive_fn = options.derive_key_fn || default_derive_key_fn(challenge.parameters.algorithm)

    key_prefix_bytes =
      if rem(String.length(key_prefix), 2) == 0 do
        Base.decode16!(key_prefix, case: :mixed)
      else
        nil
      end

    start_time = System.monotonic_time(:millisecond)
    deadline = start_time + timeout_ms

    Stream.iterate(counter_start, &(&1 + counter_step))
    |> Enum.reduce_while(nil, fn counter, _acc ->
      if System.monotonic_time(:millisecond) > deadline do
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

  Returns a `%Altcha.V2.VerifySolutionResult{}`.

  ## Options

  See `Altcha.V2.VerifySolutionOptions` for all available options.
  """
  def verify_solution(%VerifySolutionOptions{} = options) do
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

      not signature_valid?(hmac_algorithm, challenge.parameters, challenge.signature, options.hmac_signature_secret) ->
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
  """
  def verify_server_signature(payload, hmac_secret) do
    payload =
      case payload do
        %ServerSignaturePayload{} = p ->
          p

        %{} = map ->
          ServerSignaturePayload.from_map(map)

        binary when is_binary(binary) ->
          json =
            case Base.decode64(binary) do
              {:ok, decoded} -> decoded
              :error -> binary
            end

          ServerSignaturePayload.from_json(json)
      end

    start_time = System.monotonic_time(:millisecond)

    digest = sha_digest(payload.algorithm)
    hash_data = :crypto.hash(digest, payload.verification_data)
    expected_signature = do_hmac_hex(hash_data, digest, hmac_secret)

    verification_data = parse_verification_data(payload.verification_data)

    now = DateTime.to_unix(DateTime.utc_now(), :second)

    expired =
      is_map(verification_data) and
        is_integer(verification_data["expire"]) and
        verification_data["expire"] < now

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

  # ---------------------------------------------------------------------------
  # Internal helpers (exposed for testing)
  # ---------------------------------------------------------------------------

  @doc false
  def password_buffer(nonce_bytes, counter, :uint32) do
    nonce_bytes <> <<counter::32-big>>
  end

  def password_buffer(nonce_bytes, counter, :string) do
    nonce_bytes <> Integer.to_string(counter)
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

  defp sign_challenge(hmac_algorithm, parameters, derived_key, hmac_signature_secret, hmac_key_signature_secret) do
    parameters =
      if derived_key && hmac_key_signature_secret do
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
    if challenge.parameters.key_signature && options.hmac_key_signature_secret do
      # Fast path: verify HMAC of the derived key
      derived_key_bytes = Base.decode16!(solution.derived_key, case: :mixed)
      expected_key_sig = do_hmac_hex(derived_key_bytes, hmac_algorithm, options.hmac_key_signature_secret)
      valid = constant_time_equal?(challenge.parameters.key_signature, expected_key_sig)

      %VerifySolutionResult{
        expired: false,
        invalid_signature: false,
        invalid_solution: !valid,
        time: elapsed(start_time),
        verified: valid
      }
    else
      # Re-derive the key from the solution counter and compare
      counter_mode = options.counter_mode || @default_counter_mode
      derive_fn = options.derive_key_fn || default_derive_key_fn(challenge.parameters.algorithm)

      nonce_bytes = Base.decode16!(challenge.parameters.nonce, case: :mixed)
      salt_bytes = Base.decode16!(challenge.parameters.salt, case: :mixed)
      password = password_buffer(nonce_bytes, solution.counter, counter_mode)

      expected_key = derive_fn.(challenge.parameters, salt_bytes, password)
      expected_key_hex = Base.encode16(expected_key, case: :lower)

      valid = constant_time_equal?(expected_key_hex, solution.derived_key)

      %VerifySolutionResult{
        expired: false,
        invalid_signature: false,
        invalid_solution: !valid,
        time: elapsed(start_time),
        verified: valid
      }
    end
  end

  defp key_matches?(derived_key, nil, key_prefix) do
    Base.encode16(derived_key, case: :lower) |> String.starts_with?(key_prefix)
  end

  defp key_matches?(derived_key, key_prefix_bytes, _key_prefix) do
    prefix_len = byte_size(key_prefix_bytes)

    byte_size(derived_key) >= prefix_len and
      binary_part(derived_key, 0, prefix_len) == key_prefix_bytes
  end

  defp encode_canonical_object(fields) do
    entries =
      Enum.map(fields, fn {k, v} ->
        Jason.encode!(k) <> ":" <> encode_canonical_value(v)
      end)

    "{" <> Enum.join(entries, ",") <> "}"
  end

  defp encode_canonical_value(v) when is_map(v) do
    v
    |> Enum.sort_by(fn {k, _} -> k end)
    |> encode_canonical_object()
  end

  defp encode_canonical_value(v), do: Jason.encode!(v)

  defp do_hmac_hex(data, :sha256, key), do: :crypto.mac(:hmac, :sha256, key, data) |> Base.encode16() |> String.downcase()
  defp do_hmac_hex(data, :sha384, key), do: :crypto.mac(:hmac, :sha384, key, data) |> Base.encode16() |> String.downcase()
  defp do_hmac_hex(data, :sha512, key), do: :crypto.mac(:hmac, :sha512, key, data) |> Base.encode16() |> String.downcase()

  defp constant_time_equal?(a, b) when byte_size(a) != byte_size(b), do: false

  defp constant_time_equal?(a, b) do
    import Bitwise

    :binary.bin_to_list(a)
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc -> acc ||| bxor(x, y) end)
    |> Kernel.==(0)
  end

  defp is_expired?(%ChallengeParameters{expires_at: nil}), do: false

  defp is_expired?(%ChallengeParameters{expires_at: expires_at}) do
    DateTime.to_unix(DateTime.utc_now(), :second) > expires_at
  end

  defp elapsed(start_time), do: System.monotonic_time(:millisecond) - start_time

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
          Regex.match?(~r/^\d+$/, v) -> String.to_integer(v)
          Regex.match?(~r/^\d+\.\d+$/, v) -> String.to_float(v)
          k in convert_to_list and v != "" -> v |> String.trim() |> String.split(",")
          true -> String.trim(v)
        end

      {k, value}
    end)
  rescue
    _ -> nil
  end
end
