# ALTCHA Elixir Library

The ALTCHA Elixir Library is a lightweight library designed for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

This library is compatible with:

- Elixir 1.10+

## Example

- [Demo server](https://github.com/altcha-org/altcha-starter-ex)

## Installation

To install the ALTCHA Elixir Library, add it to your `mix.exs` dependencies:

```elixir
defp deps do
  [
    {:altcha, "~> 0.1"}
  ]
end
```

Then run:

```sh
mix deps.get
```

## Usage

Here’s a basic example of how to use the ALTCHA Elixir Library:

```elixir
hmac_key = "secret hmac key"

# Create a new challenge
options = %Altcha.ChallengeOptions{
  hmac_key: hmac_key,
  max_number: 100000 # the maximum random number
}

challenge = Altcha.create_challenge(options)

# Example payload to verify
payload = %{
  algorithm: challenge.algorithm,
  challenge: challenge.challenge,
  number: 123, # Example number
  salt: challenge.salt,
  signature: challenge.signature
}

# Verify the solution
valid = Altcha.verify_solution(payload, hmac_key, true)
```

## API Documentation

### `create_challenge/1`

**Description:**

Generates a new ALTCHA challenge with the specified options. The challenge includes a hashed string and an HMAC signature.

**Parameters:**

- `%ChallengeOptions{}` - A struct containing options for challenge creation:

  - `:algorithm` - (optional) The algorithm to use for hashing (`:sha`, `:sha256`, `:sha512`). Defaults to `:sha256`.
  - `:max_number` - (optional) The maximum number for challenge generation. Defaults to `1_000_000`.
  - `:salt_length` - (optional) The length of the salt. Defaults to `12`.
  - `:hmac_key` - (required) Key used for HMAC calculation.
  - `:salt` - (optional) The salt value. If not provided, a random salt will be generated.
  - `:number` - (optional) The number for the challenge. If not provided, a random number will be generated.
  - `:expires` - (optional) Expiration time for the challenge in seconds from the current time.
  - `:params` - (optional) Additional parameters to include in the salt.

**Returns:**

A `%Challenge{}` struct containing:

- `:algorithm` - The hashing algorithm used.
- `:challenge` - The hashed challenge string.
- `:maxnumber` - The maximum number used.
- `:salt` - The salt used.
- `:signature` - The HMAC signature of the challenge.

---

### `verify_solution/2`

**Description:**

Verifies a given solution by checking its validity and comparing it with the expected challenge.

**Parameters:**

- `payload` - The payload containing challenge details. Can be a `%Payload{}` struct, a JSON object, or a Base64-encoded string.
- `hmac_key` - The key used for HMAC calculation.

**Options:**

- `check_expires` - (optional) A boolean to determine if the expiration of the challenge should be checked. Defaults to `true`.

**Returns:**

`true` if the solution is valid and matches the expected challenge; otherwise, `false`.

---

### `verify_fields_hash/4`

**Description:**

Verifies if the hash of form fields matches the provided hash.

**Parameters:**

- `form_data` - The form data as a map with field names and values.
- `fields` - A list of field names to be included in the hash calculation.
- `fields_hash` - The expected hash of the form fields.
- `algorithm` - The algorithm used for hashing (`:sha`, `:sha256`, `:sha512`).

**Returns:**

`true` if the computed hash of the fields matches the provided hash; otherwise, `false`.

---

### `verify_server_signature/2`

**Description:**

Verifies the server signature using the provided payload and HMAC key.

**Parameters:**

- `payload` - The payload containing server signature details. Can be a `%ServerSignaturePayload{}` struct, a JSON object, or a Base64-encoded string.
- `hmac_key` - The key used for HMAC calculation.

**Returns:**

`true` if the server signature is valid and matches the expected signature; otherwise, `false`.

---

### `solve_challenge/4`

**Description:**

Attempts to solve a given challenge by searching for a number that matches the challenge criteria.

**Parameters:**

- `challenge` - The challenge string to be matched.
- `salt` - The salt used in challenge generation.
- `algorithm` - (optional) The algorithm used for hashing (`:sha`, `:sha256`, `:sha512`). Defaults to `:sha256`.
- `max` - (optional) The maximum number to search. Defaults to `1_000_000`.
- `start` - (optional) The starting number for the search. Defaults to `0`.

**Returns:**

A `%Solution{}` struct containing:

- `:number` - The number that solves the challenge.
- `:took` - The time taken to find the solution in milliseconds.

If no solution is found, returns `nil`.


## License

MIT