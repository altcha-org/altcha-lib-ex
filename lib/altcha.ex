defmodule Altcha do
  @moduledoc """
  Altcha module provides functions for creating and verifying ALTCHA challenges.
  """

  @algorithm_sha "SHA-1"
  @algorithm_sha256 "SHA-256"
  @algorithm_sha512 "SHA-512"

  @default_max_number 1_000_000
  @default_salt_length 12
  @default_algorithm :sha256

  defmodule ChallengeOptions do
    @moduledoc """
    Represents options for generating a challenge.
    """
    defstruct [
      # Algorithm to use for hashing
      :algorithm,
      # Maximum number for challenge generation
      :max_number,
      # Length of the salt
      :salt_length,
      # Key used for HMAC
      :hmac_key,
      # Salt value
      :salt,
      # Number for the challenge
      :number,
      # Expiration time for the challenge
      :expires,
      # Additional parameters
      :params
    ]
  end

  defmodule Challenge do
    @moduledoc """
    Represents a challenge with its attributes.
    """
    defstruct [
      # Hashing algorithm used
      :algorithm,
      # The generated challenge string
      :challenge,
      # Maximum number used
      :maxnumber,
      # Salt used in challenge generation
      :salt,
      # Signature for the challenge
      :signature
    ]

    @doc """
    Converts a `Challenge` struct to JSON.
    """
    def to_json(%Challenge{
          algorithm: algorithm,
          challenge: challenge,
          maxnumber: maxnumber,
          salt: salt,
          signature: signature
        }) do
      %{
        algorithm: Altcha.algorithm_to_binary(algorithm),
        challenge: challenge,
        maxnumber: maxnumber,
        salt: salt,
        signature: signature
      }
      |> Jason.encode!()
    end
  end

  defmodule Payload do
    @moduledoc """
    Represents the payload of a challenge.
    """
    defstruct [
      # Algorithm used for hashing
      :algorithm,
      # The challenge string
      :challenge,
      # Number used in the challenge
      :number,
      # Salt used in the challenge
      :salt,
      # Signature for the challenge
      :signature
    ]

    @doc """
    Converts a `Payload` struct to JSON.
    """
    def to_json(%Payload{
          algorithm: algorithm,
          challenge: challenge,
          number: number,
          salt: salt,
          signature: signature
        }) do
      %{
        algorithm: Altcha.algorithm_to_binary(algorithm),
        challenge: challenge,
        number: number,
        salt: salt,
        signature: signature
      }
      |> Jason.encode!()
    end

    @doc """
    Converts JSON to a `Payload` struct.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        |> Enum.map(fn
          {"algorithm", alg} ->
            {:algorithm, Altcha.algorithm_from_binary(alg)}

          {"number", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            {:number, value}

          {k, v} ->
            {String.to_atom(k), v}
        end)

      struct(__MODULE__, map)
    end
  end

  defmodule ServerSignaturePayload do
    @moduledoc """
    Represents the payload for server signatures.
    """
    defstruct [
      # Algorithm used for hashing
      :algorithm,
      # Data used for verification
      :verification_data,
      # Signature for verification
      :signature,
      # Flag indicating if the signature is verified
      :verified
    ]

    @doc """
    Converts a `ServerSignaturePayload` struct to JSON.
    """
    def to_json(%ServerSignaturePayload{
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
      |> Jason.encode!()
    end

    @doc """
    Converts JSON to a `ServerSignaturePayload` struct.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        |> Enum.map(fn
          {"algorithm", alg} ->
            {:algorithm, Altcha.algorithm_from_binary(alg)}

          {"verificationData", v} ->
            {:verification_data, v}

          {k, v} ->
            {String.to_atom(k), v}
        end)
        |> Enum.into(%{})

      struct(__MODULE__, map)
    end
  end

  defmodule ServerSignatureVerificationData do
    @moduledoc """
    Represents data for verifying server signatures, including various data points.
    """
    defstruct [
      # Classification of the data
      :classification,
      # Country information
      :country,
      # Detected language
      :detected_language,
      # Email address
      :email,
      # Expiration time
      :expire,
      # Form fields
      :fields,
      # Hash of the form fields
      :fields_hash,
      # IP address
      :ip_address,
      # Reasons for verification
      :reasons,
      # Score of the verification
      :score,
      # Time of verification
      :time,
      # Flag indicating if the verification is successful
      :verified
    ]

    @doc """
    Converts a `ServerSignatureVerificationData` struct to JSON.
    """
    def to_json(%ServerSignatureVerificationData{
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
      |> Jason.encode!()
    end

    @doc """
    Converts JSON to a `ServerSignatureVerificationData` struct.
    """
    def from_json(json) do
      map =
        json
        |> Jason.decode!()
        |> Enum.map(fn
          {"expire", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            {:expire, value}

          {"fields", fields} ->
            {:fields, String.split(fields, ",")}

          {"reasons", reasons} ->
            {:reasons, String.split(reasons, ",")}

          {"score", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            {:score, value}

          {"time", n} ->
            value = if is_integer(n), do: n, else: String.to_integer(n)
            {:time, value}

          {k, v} ->
            {String.to_atom(k), v}
        end)

      struct(__MODULE__, map)
    end
  end

  defmodule Solution do
    @moduledoc """
    Represents the solution to a challenge.
    """
    defstruct [
      # The number that solves the challenge
      :number,
      # Time taken to solve the challenge (in milliseconds)
      :took
    ]
  end

  @doc """
  Generates a specified number of random bytes.
  """
  def random_bytes(length) do
    :crypto.strong_rand_bytes(length)
  end

  @doc """
  Generates a random integer between 0 and the given maximum value.
  """
  def random_int(max) do
    :rand.uniform(max + 1) - 1
  end

  @doc """
  Converts an algorithm name from binary format to an atom.
  """
  def algorithm_from_binary(algorithm) do
    case algorithm do
      @algorithm_sha -> :sha
      @algorithm_sha256 -> :sha256
      @algorithm_sha512 -> :sha512
      _ ->
        if is_atom(algorithm), do: algorithm, else: String.to_atom(algorithm)
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
      _ ->
        if is_atom(algorithm), do: algorithm, else: Atom.to_string(algorithm)
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
        Map.put(
          params,
          "expires",
          Integer.to_string(DateTime.to_unix(DateTime.utc_now(), :second))
        )
      else
        params
      end

    salt = salt || random_bytes(salt_length) |> Base.encode16()

    salt =
      if params != %{} do
        salt <> "?#{URI.encode_query(params)}"
      else
        salt
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

    if payload_is_valid?(payload) do
      if check_expires and String.contains?(payload.salt, "?") do
        expires =
          payload.salt
          |> String.split("?")
          |> List.last()
          |> URI.decode_query()
          |> Map.get("expires")
          |> String.to_integer()

        if DateTime.to_unix(DateTime.utc_now(), :second) > expires, do: false
      end

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
      payload.signature == expected_signature
    else
      false
    end
  rescue
    ArgumentError -> false
    Jason.DecodeError -> false
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
