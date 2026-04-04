# ALTCHA Elixir Library

A lightweight Elixir library for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

- Elixir 1.17+ (OTP 26+)

## Examples

- [`examples/server/`](/examples/server/)
- [`examples/argon2.exs`](/examples/argon2.exs)

## Installation

```elixir
defp deps do
  [
    {:altcha, "~> 2.0"}
  ]
end
```

## Versions

The library supports two proof-of-work versions:

| Module | Algorithm | Use with |
|--------|-----------|----------|
| `Altcha.V1` | Hash-based (`SHA-256` etc.) | ALTCHA widget v1 |
| `Altcha.V2` | Key-derivation-based (`PBKDF2`, iterative `SHA`) | ALTCHA widget v2 |

The top-level `Altcha` module delegates to `Altcha.V1` for backward compatibility.

---

## V2 Usage

### Creating a challenge

```elixir
challenge = Altcha.V2.create_challenge(%Altcha.V2.CreateChallengeOptions{
  algorithm: "PBKDF2/SHA-256",
  cost: 10_000,
  hmac_signature_secret: "your-secret"
})

# Send as JSON to the client
Jason.encode!(challenge)
```

For deterministic mode (random counter, faster server-side verification):

```elixir
challenge = Altcha.V2.create_challenge(%Altcha.V2.CreateChallengeOptions{
  algorithm: "PBKDF2/SHA-256",
  cost: 5_000,
  counter: Enum.random(5_000..10_000),
  expires_at: DateTime.to_unix(DateTime.utc_now(), :second) + 600,
  hmac_signature_secret: "your-secret",
  hmac_key_signature_secret: "your-key-secret"
})
```

With `counter` and `hmac_key_signature_secret`, the server pre-computes the expected derived key and signs it. Verification then checks the HMAC of the submitted key instead of re-running the key derivation.

### Verifying a solution

The client submits a Base64-encoded JSON payload containing the challenge and solution:

```elixir
# Decode the client payload
payload = Altcha.V2.decode_payload(params["altcha"])

result = Altcha.V2.verify_solution(%Altcha.V2.VerifySolutionOptions{
  challenge: payload.challenge,
  solution: payload.solution,
  hmac_signature_secret: "your-secret",
  hmac_key_signature_secret: "your-key-secret"  # optional
})

result.verified       # true / false
result.expired        # true if the challenge has expired
result.invalid_signature  # true if the challenge was tampered with
result.invalid_solution   # true if the solution is incorrect
```

### Verifying a server signature

```elixir
{result, verification_data} = Altcha.V2.verify_server_signature(params["altcha"], "your-secret")

result.verified           # true / false
verification_data["email"]      # values parsed from verificationData
verification_data["verified"]   # boolean
verification_data["expire"]     # integer Unix timestamp
```

`verify_server_signature/2` accepts a `%Altcha.V2.ServerSignaturePayload{}` struct, a plain map, a raw JSON string, or a Base64-encoded JSON string.

### Verifying form fields hash

```elixir
Altcha.V2.verify_fields_hash(form_data, ["email", "message"], fields_hash, "SHA-256")
```

### Supported algorithms

| Algorithm string | Description |
|-----------------|-------------|
| `"SHA-256"` / `"SHA-384"` / `"SHA-512"` | Iterative SHA hashing (built-in) |
| `"PBKDF2/SHA-256"` / `"PBKDF2/SHA-384"` / `"PBKDF2/SHA-512"` | PBKDF2 (requires OTP 24+) |
| Custom | Pass a `derive_key_fn` option |

### Custom key derivation

For algorithms not built-in (e.g. Scrypt, Argon2id), provide a `derive_key_fn`:

```elixir
Altcha.V2.create_challenge(%Altcha.V2.CreateChallengeOptions{
  algorithm: "SCRYPT",
  cost: 16_384,
  memory_cost: 8,
  derive_key_fn: fn params, salt, password ->
    # return derived key as binary
  end,
  hmac_signature_secret: "your-secret"
})
```

---

## V1 Usage

```elixir
challenge = Altcha.V1.create_challenge(%Altcha.V1.ChallengeOptions{
  hmac_key: "your-secret",
  max_number: 100_000,
  expires: DateTime.to_unix(DateTime.utc_now(), :second) + 600
})

# Verify a solution submitted by the client
Altcha.V1.verify_solution(params["altcha"], "your-secret")

# Verify a server signature
{verified, verification_data} = Altcha.V1.verify_server_signature(params["altcha"], "your-secret")

# Verify form fields hash
Altcha.V1.verify_fields_hash(form_data, ["email", "message"], fields_hash, :sha256)
```

---

## License

MIT
