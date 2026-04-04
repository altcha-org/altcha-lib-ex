defmodule Altcha.V2.Algorithms.SHA do
  @moduledoc """
  Iterative SHA key derivation for PoW v2 challenges.

  Computes: hash(hash(...hash(salt ++ password)...)) for `cost` total iterations.
  Supported algorithm strings: "SHA-256", "SHA-384", "SHA-512".
  """

  @doc """
  Derives a key by iteratively hashing salt concatenated with password.

  Parameters:
  - `parameters` - challenge parameters (uses `:algorithm`, `:cost`, `:key_length`)
  - `salt` - raw salt bytes
  - `password` - raw password bytes (nonce + counter)

  Returns the derived key as a binary.
  """
  def derive_key(%{algorithm: algorithm, cost: cost, key_length: key_length}, salt, password) do
    digest = get_digest(algorithm)
    key_length = key_length || 32
    iterations = max(1, cost)

    derived_key =
      Enum.reduce(1..iterations, salt <> password, fn _i, acc ->
        :crypto.hash(digest, acc)
      end)

    binary_part(derived_key, 0, min(key_length, byte_size(derived_key)))
  end

  defp get_digest("SHA-512"), do: :sha512
  defp get_digest("SHA-384"), do: :sha384
  defp get_digest(_), do: :sha256
end
