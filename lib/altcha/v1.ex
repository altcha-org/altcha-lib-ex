defmodule Altcha.V1 do
  @moduledoc """
  Altcha V1 module provides functions for creating and verifying ALTCHA challenges
  using the original proof-of-work algorithm (hash-based).
  """

  @algorithm_sha "SHA-1"
  @algorithm_sha256 "SHA-256"
  @algorithm_sha512 "SHA-512"

  @default_max_number 1_000_000
  @default_salt_length 12
  @default_algorithm :sha256

  defmodule ChallengeOptions do
    @moduledoc """
    Represents options for generating a V1 challenge.
    """
    defstruct [
      :algorithm,
      :max_number,
      :salt_length,
      :hmac_key,
      :salt,
      :number,
      :expires,
      :params
    ]
  end

  defmodule Challenge do
    @moduledoc """
    Represents a V1 challenge with its attributes.
    """
    defstruct [
      :algorithm,
      :challenge,
      :maxnumber,
      :salt,
      :signature
    ]

    defimpl Jason.Encoder do
      def encode(challenge, opts) do
        Jason.Encode.map(Challenge.to_map(challenge), opts)
      end
    end

    if Code.ensure_loaded?(JSON.Encoder) do
      defimpl JSON.Encoder do
        def encode(challenge, encoder) do
          JSON.Encoder.encode(Challenge.to_map(challenge), encoder)
        end
      end
    end

    @doc """
    Converts a `Challenge` struct to a JSON-encodable map in the wire format.
    """
    def to_map(%Challenge{
          algorithm: algorithm,
          challenge: challenge,
          maxnumber: maxnumber,
          salt: salt,
          signature: signature
        }) do
      %{
        algorithm: Altcha.V1.algorithm_to_binary(algorithm),
        challenge: challenge,
        maxnumber: maxnumber,
        salt: salt,
        signature: signature
      }
    end

    @doc """
    Converts a `Challenge` struct to JSON.
    """
    def to_json(%Challenge{} = challenge), do: challenge |> to_map() |> Jason.encode!()
  end

  defmodule Payload do
    @moduledoc """
    Represents the payload of a V1 challenge.
    """
    defstruct [
      :algorithm,
      :challenge,
      :number,
      :salt,
      :signature
    ]

    defimpl Jason.Encoder do
      def encode(payload, opts) do
        Jason.Encode.map(Payload.to_map(payload), opts)
      end
    end

    if Code.ensure_loaded?(JSON.Encoder) do
      defimpl JSON.Encoder do
        def encode(payload, encoder) do
          JSON.Encoder.encode(Payload.to_map(payload), encoder)
        end
      end
    end

    @doc """
    Converts a `Payload` struct to a JSON-encodable map in the wire format.
    """
    def to_map(%Payload{
          algorithm: algorithm,
          challenge: challenge,
          number: number,
          salt: salt,
          signature: signature
        }) do
      %{
        algorithm: Altcha.V1.algorithm_to_binary(algorithm),
        challenge: challenge,
        number: number,
        salt: salt,
        signature: signature
      }
    end

    @doc """
    Converts a `Payload` struct to JSON.
    """
    def to_json(%Payload{} = payload), do: payload |> to_map() |> Jason.encode!()

    @doc """
    Converts JSON to a `Payload` struct. Unknown keys are ignored.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        # Map known keys explicitly: atoms are never garbage-collected, so
        # creating them from client-supplied keys would exhaust the atom table.
        |> Enum.flat_map(fn
          {"algorithm", alg} ->
            [{:algorithm, Altcha.V1.algorithm_from_binary(alg)}]

          {"number", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            [{:number, value}]

          {"challenge", v} ->
            [{:challenge, v}]

          {"salt", v} ->
            [{:salt, v}]

          {"signature", v} ->
            [{:signature, v}]

          _ ->
            []
        end)

      struct(__MODULE__, map)
    end
  end

  defmodule ServerSignaturePayload do
    @moduledoc """
    Represents the payload for server signatures.
    """
    defstruct [
      :algorithm,
      :verification_data,
      :signature,
      :verified
    ]

    defimpl Jason.Encoder do
      def encode(signature_payload, opts) do
        Jason.Encode.map(ServerSignaturePayload.to_map(signature_payload), opts)
      end
    end

    if Code.ensure_loaded?(JSON.Encoder) do
      defimpl JSON.Encoder do
        def encode(signature_payload, encoder) do
          JSON.Encoder.encode(ServerSignaturePayload.to_map(signature_payload), encoder)
        end
      end
    end

    @doc """
    Converts a `ServerSignaturePayload` struct to a JSON-encodable map in the wire format.
    """
    def to_map(%ServerSignaturePayload{
          algorithm: algorithm,
          verification_data: verification_data,
          signature: signature,
          verified: verified
        }) do
      %{
        algorithm: algorithm,
        verificationData: verification_data,
        signature: signature,
        verified: verified
      }
    end

    @doc """
    Converts a `ServerSignaturePayload` struct to JSON.
    """
    def to_json(%ServerSignaturePayload{} = signature_payload),
      do: signature_payload |> to_map() |> Jason.encode!()

    @doc """
    Converts JSON to a `ServerSignaturePayload` struct. Unknown keys are ignored.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        # Map known keys explicitly; see `Payload.from_json/1`.
        |> Enum.flat_map(fn
          {"algorithm", alg} ->
            [{:algorithm, Altcha.V1.algorithm_from_binary(alg)}]

          {"verificationData", v} ->
            [{:verification_data, v}]

          {"signature", v} ->
            [{:signature, v}]

          {"verified", v} ->
            [{:verified, v}]

          _ ->
            []
        end)

      struct(__MODULE__, map)
    end
  end

  defmodule ServerSignatureVerificationData do
    @moduledoc """
    Represents data for verifying server signatures.
    """
    defstruct [
      :classification,
      :country,
      :detected_language,
      :email,
      :expire,
      :fields,
      :fields_hash,
      :ip_address,
      :reasons,
      :score,
      :time,
      :verified
    ]

    defimpl Jason.Encoder do
      def encode(verification_data, opts) do
        Jason.Encode.map(ServerSignatureVerificationData.to_map(verification_data), opts)
      end
    end

    if Code.ensure_loaded?(JSON.Encoder) do
      defimpl JSON.Encoder do
        def encode(verification_data, encoder) do
          JSON.Encoder.encode(ServerSignatureVerificationData.to_map(verification_data), encoder)
        end
      end
    end

    @doc """
    Converts a `ServerSignatureVerificationData` struct to a JSON-encodable map in the
    wire format.
    """
    def to_map(%ServerSignatureVerificationData{
          classification: classification,
          country: country,
          detected_language: detected_language,
          email: email,
          expire: expire,
          fields: fields,
          fields_hash: fields_hash,
          ip_address: ip_address,
          reasons: reasons,
          score: score,
          time: time,
          verified: verified
        }) do
      %{
        classification: classification,
        country: country,
        detectedLanguage: detected_language,
        email: email,
        expire: expire,
        fields: fields,
        fieldsHash: fields_hash,
        ipAddress: ip_address,
        reasons: reasons,
        score: score,
        time: time,
        verified: verified
      }
    end

    @doc """
    Converts a `ServerSignatureVerificationData` struct to JSON.
    """
    def to_json(%ServerSignatureVerificationData{} = verification_data),
      do: verification_data |> to_map() |> Jason.encode!()

    @doc """
    Converts JSON to a `ServerSignatureVerificationData` struct. Unknown keys are ignored.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        # Map known keys explicitly; see `Payload.from_json/1`.
        |> Enum.flat_map(fn
          {"classification", v} ->
            [{:classification, v}]

          {"country", v} ->
            [{:country, v}]

          {"detectedLanguage", v} ->
            [{:detected_language, v}]

          {"email", v} ->
            [{:email, v}]

          {"expire", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            [{:expire, value}]

          {"fields", fields} ->
            [{:fields, String.split(fields, ",")}]

          {"fieldsHash", fields_hash} ->
            [{:fields_hash, fields_hash}]

          {"ipAddress", v} ->
            [{:ip_address, v}]

          {"reasons", reasons} ->
            [{:reasons, String.split(reasons, ",")}]

          {"score", n} ->
            [{:score, parse_score(n)}]

          {"time", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            [{:time, value}]

          {"verified", verified} ->
            [{:verified, verified === "true"}]

          _ ->
            []
        end)

      struct(__MODULE__, map)
    end

    # Scores are fractional (e.g. "0.5"); like the other ports, always return a float.
    defp parse_score(n) when is_number(n), do: n / 1

    defp parse_score(n) when is_binary(n) do
      case Float.parse(n) do
        {value, ""} -> value
        _ -> raise ArgumentError, "invalid score: #{inspect(n)}"
      end
    end
  end

  defmodule Solution do
    @moduledoc """
    Represents the solution to a V1 challenge.
    """
    defstruct [:number, :took]
  end

  @doc """
  Generates a specified number of random bytes.
  """
  def random_bytes(length) do
    :crypto.strong_rand_bytes(length)
  end

  @doc """
  Generates a random integer between 0 and the given maximum value (inclusive).
  """
  def random_int(max) do
    :rand.uniform(max + 1) - 1
  end

  @spec algorithm_from_binary(any()) :: any()
  @doc """
  Converts an algorithm name from binary format to an atom. Unknown names are returned
  unchanged, so they never create atoms.
  """
  def algorithm_from_binary(algorithm) do
    case algorithm do
      @algorithm_sha -> :sha
      @algorithm_sha256 -> :sha256
      @algorithm_sha512 -> :sha512
      _ -> algorithm
    end
  end

  @doc """
  Converts an algorithm atom to its binary representation.
  """
  def algorithm_to_binary(algorithm) do
    case algorithm do
      :sha -> @algorithm_sha
      :sha256 -> @algorithm_sha256
      :sha512 -> @algorithm_sha512
      _ -> if is_atom(algorithm), do: Atom.to_string(algorithm), else: algorithm
    end
  end

  @doc """
  Hashes data using the specified algorithm and returns it as a hex string.
  """
  def hash_hex(data, algorithm) do
    data
    |> hash(algorithm)
    |> Base.encode16()
    |> String.downcase()
  end

  @doc """
  Hashes data using the specified algorithm.
  """
  def hash(data, algorithm) do
    case algorithm do
      :sha -> :crypto.hash(:sha, data)
      :sha256 -> :crypto.hash(:sha256, data)
      :sha512 -> :crypto.hash(:sha512, data)
      _ -> raise ArgumentError, "Unsupported algorithm: #{algorithm}"
    end
  end

  @doc """
  Creates an HMAC from the data using the specified algorithm and key, and returns it as a hex string.
  """
  def hmac_hex(data, algorithm, key) do
    data
    |> hmac_hash(algorithm, key)
    |> Base.encode16()
    |> String.downcase()
  end

  @doc """
  Computes HMAC for the given data using the specified algorithm and key.
  """
  def hmac_hash(data, algorithm, key) do
    case algorithm do
      :sha -> :crypto.mac(:hmac, :sha, key, data)
      :sha256 -> :crypto.mac(:hmac, :sha256, key, data)
      :sha512 -> :crypto.mac(:hmac, :sha512, key, data)
      _ -> raise ArgumentError, "Unsupported algorithm: #{algorithm}"
    end
  end

  @doc """
  Creates a challenge with the specified options.
  """
  def create_challenge(%ChallengeOptions{
        algorithm: algorithm,
        max_number: max_number,
        salt_length: salt_length,
        hmac_key: hmac_key,
        salt: salt,
        number: number,
        expires: expires,
        params: params
      }) do
    algorithm = algorithm || @default_algorithm
    max_number = max_number || @default_max_number
    salt_length = salt_length || @default_salt_length

    params = params || %{}

    params =
      if expires do
        time = if is_binary(expires), do: expires, else: Integer.to_string(expires)
        Map.put(params, "expires", time)
      else
        params
      end

    salt = salt || random_bytes(salt_length) |> Base.encode16() |> String.downcase()

    salt =
      if params != %{} do
        salt <> "?#{URI.encode_query(params)}"
      else
        salt
      end

    # Add a delimiter to prevent parameter splicing
    salt =
      if String.ends_with?(salt, "&") do
        salt
      else
        salt <> "&"
      end

    number = number || random_int(max_number)

    challenge_str = "#{salt}#{number}"
    challenge = hash_hex(challenge_str, algorithm)
    signature = hmac_hex(challenge, algorithm, hmac_key)

    %Challenge{
      algorithm: algorithm,
      challenge: challenge,
      maxnumber: max_number,
      salt: salt,
      signature: signature
    }
  end

  @doc """
  Verifies a solution by checking its validity and comparing it with the expected challenge.
  """
  def verify_solution(payload, hmac_key, check_expires \\ true) do
    payload =
      case payload do
        %Payload{} = payload -> payload
        %{} -> Payload.from_json(Jason.encode!(payload))
        _ -> Payload.from_json(Base.decode64!(payload))
      end

    if payload_is_valid?(payload) and not (check_expires and expired?(payload)) do
      challenge_options = %ChallengeOptions{
        algorithm: payload.algorithm,
        hmac_key: hmac_key,
        number: payload.number,
        salt: payload.salt
      }

      expected_challenge = create_challenge(challenge_options)

      expected_challenge.challenge == payload.challenge and
        expected_challenge.signature == payload.signature
    else
      false
    end
  rescue
    ArgumentError -> false
    Jason.DecodeError -> false
  end

  @doc """
  Extracts parameters from the payload's salt.
  """
  def extract_params(%Payload{salt: salt}) do
    salt
    |> String.split("?")
    |> List.last()
    |> URI.decode_query()
  end

  @doc """
  Verifies if the hash of form fields matches the provided hash.
  """
  def verify_fields_hash(form_data, fields, fields_hash, algorithm) do
    lines = fields |> Enum.map(&(Map.get(form_data, &1, "") |> to_string()))
    joined_data = Enum.join(lines, "\n")
    computed_hash = hash_hex(joined_data, algorithm)
    computed_hash == fields_hash
  end

  @doc """
  Verifies the server signature using the payload and HMAC key.
  """
  def verify_server_signature(payload, hmac_key) do
    payload =
      case payload do
        %ServerSignaturePayload{} = payload -> payload
        %{} -> ServerSignaturePayload.from_json(Jason.encode!(payload))
        _ -> ServerSignaturePayload.from_json(Base.decode64!(payload))
      end

    if server_verification_payload_is_valid?(payload) do
      hash_data = hash(payload.verification_data, payload.algorithm)
      expected_signature = hmac_hex(hash_data, payload.algorithm, hmac_key)

      verification_data =
        ServerSignatureVerificationData.from_json(
          Jason.encode!(URI.decode_query(payload.verification_data))
        )

      now = DateTime.to_unix(DateTime.utc_now(), :second)

      is_verified =
        payload.verified &&
          verification_data.verified == true &&
          (verification_data.expire == nil || verification_data.expire > now) &&
          payload.signature == expected_signature

      {is_verified, verification_data}
    else
      {false, nil}
    end
  end

  @doc """
  Solves a challenge by searching for a number that matches the given challenge.
  """
  def solve_challenge(
        challenge,
        salt,
        algorithm \\ @default_algorithm,
        max \\ @default_max_number,
        start \\ 0
      ) do
    start_time = :os.system_time(:millisecond)

    Enum.reduce_while(start..max, nil, fn n, _acc ->
      hash = hash_hex("#{salt}#{n}", algorithm)

      if hash == challenge do
        took = :os.system_time(:millisecond) - start_time
        solution = %Solution{number: n, took: took}
        {:halt, solution}
      else
        {:cont, nil}
      end
    end)
  end

  defp payload_is_valid?(%{
         algorithm: algorithm,
         number: number,
         challenge: challenge,
         signature: signature,
         salt: salt
       })
       when is_atom(algorithm) and is_integer(number) and is_binary(challenge) and
              is_binary(signature) and
              is_binary(salt),
       do: true

  defp payload_is_valid?(_), do: false

  # A salt without "expires" has no expiry. A non-numeric "expires" raises
  # ArgumentError, which verify_solution/3 turns into false.
  defp expired?(%Payload{salt: salt} = payload) do
    with true <- String.contains?(salt, "?"),
         {:ok, expires} <- Map.fetch(extract_params(payload), "expires") do
      DateTime.to_unix(DateTime.utc_now(), :second) > String.to_integer(expires)
    else
      _ -> false
    end
  end

  defp server_verification_payload_is_valid?(%{
         algorithm: algorithm,
         verification_data: verification_data,
         verified: verified,
         signature: signature
       })
       when is_atom(algorithm) and is_binary(verification_data) and is_binary(signature) and
              is_boolean(verified),
       do: true

  defp server_verification_payload_is_valid?(_), do: false
end
