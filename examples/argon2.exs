# Argon2id challenge generation example
#
# Requires libargon2 to be installed on the system:
#   macOS:  brew install argon2
#   Debian: apt install libargon2-dev
#
# Run from the repository root:
#   elixir examples/argon2.exs

Mix.install([
  {:altcha, path: "."},
  {:argon2_elixir, "~> 3.0"},
  {:jason, "~> 1.4"}
])

defmodule Argon2Example do
  alias Altcha.V2
  alias Altcha.V2.{CreateChallengeOptions, SolveChallengeOptions, VerifySolutionOptions}

  @hmac_secret "example-secret"
  @hmac_key_secret "example-key-secret"

  # Argon2id derive_key_fn matching the JS reference implementation:
  #   argon2id(message: password, nonce: salt, passes: cost, memory: memory_cost, ...)
  #
  # Notes:
  #   - argon2_elixir's m_cost is log₂ of the memory in KiB, while V2's memory_cost
  #     is the raw KiB value (matching the JS convention). Convert with trunc(log₂(memory_cost)).
  #   - argon2_elixir returns a lowercase hex string with format: :raw_hash; decode it
  #     back to raw bytes so the derive_key_fn contract (raw binary) is satisfied.
  def derive_key(params, salt, password) do
    m_cost_log2 = params.memory_cost |> :math.log2() |> trunc()

    Argon2.Base.hash_password(
      password,
      salt,
      t_cost: params.cost,
      m_cost: m_cost_log2,
      parallelism: params.parallelism || 1,
      hashlen: params.key_length || 32,
      argon2_type: 2,
      format: :raw_hash
    )
    |> Base.decode16!(case: :lower)
  end

  def run do
    IO.puts("==> Creating Argon2id challenge (deterministic mode)...\n")

    challenge =
      V2.create_challenge(%CreateChallengeOptions{
        algorithm: "ARGON2ID",
        cost: 1,
        memory_cost: 65_536,
        parallelism: 1,
        counter: Enum.random(1..100),
        derive_key_fn: &derive_key/3,
        expires_at: DateTime.to_unix(DateTime.utc_now(), :second) + 600,
        hmac_signature_secret: @hmac_secret,
        hmac_key_signature_secret: @hmac_key_secret
      })

    IO.puts(Jason.encode!(challenge, pretty: true))

    IO.puts("\n==> Solving challenge...\n")

    solution =
      V2.solve_challenge(%SolveChallengeOptions{
        challenge: challenge,
        derive_key_fn: &derive_key/3
      })

    IO.puts("counter    : #{solution.counter}")
    IO.puts("derived_key: #{solution.derived_key}")
    IO.puts("time       : #{solution.time}ms")

    IO.puts("\n==> Verifying solution...\n")

    result =
      V2.verify_solution(%VerifySolutionOptions{
        challenge: challenge,
        solution: solution,
        derive_key_fn: &derive_key/3,
        hmac_signature_secret: @hmac_secret,
        hmac_key_signature_secret: @hmac_key_secret
      })

    IO.puts("verified          : #{result.verified}")
    IO.puts("expired           : #{result.expired}")
    IO.puts("invalid_signature : #{result.invalid_signature}")
    IO.puts("invalid_solution  : #{result.invalid_solution}")
    IO.puts("time              : #{result.time}ms")
  end
end

Argon2Example.run()
