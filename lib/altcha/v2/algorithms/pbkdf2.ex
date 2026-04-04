defmodule Altcha.V2.Algorithms.PBKDF2 do
  @moduledoc """
  PBKDF2 key derivation for PoW v2 challenges.

  Requires Erlang OTP 24 or later (`crypto:pbkdf2_hmac/5`).
  Supported algorithm strings: "PBKDF2/SHA-256", "PBKDF2/SHA-384", "PBKDF2/SHA-512".
  """

  @doc """
  Derives a key using PBKDF2-HMAC.

  Parameters:
  - `parameters` - challenge parameters (uses `:algorithm`, `:cost`, `:key_length`)
  - `salt` - raw salt bytes
  - `password` - raw password bytes (nonce + counter)

  Returns the derived key as a binary.
  """
  def derive_key(%{algorithm: algorithm, cost: cost, key_length: key_length}, salt, password) do
    digest = get_digest(algorithm)
    key_length = key_length || 32

    :crypto.pbkdf2_hmac(digest, password, salt, cost, key_length)
  end

  defp get_digest("PBKDF2/SHA-512"), do: :sha512
  defp get_digest("PBKDF2/SHA-384"), do: :sha384
  defp get_digest(_), do: :sha256
end
