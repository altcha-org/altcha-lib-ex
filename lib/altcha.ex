defmodule Altcha do
  @moduledoc """
  Top-level Altcha module providing backward-compatible access to V1 functions.

  ## Versioned namespaces

  - `Altcha.V1` — original hash-based proof-of-work (SHA-1/256/512)
  - `Altcha.V2` — key-derivation-based proof-of-work (PBKDF2, iterative SHA)

  All functions in this module delegate to `Altcha.V1`.
  New code should use `Altcha.V1` or `Altcha.V2` explicitly.
  """

  defdelegate random_bytes(length), to: Altcha.V1
  defdelegate random_int(max), to: Altcha.V1
  defdelegate algorithm_from_binary(algorithm), to: Altcha.V1
  defdelegate algorithm_to_binary(algorithm), to: Altcha.V1
  defdelegate hash(data, algorithm), to: Altcha.V1
  defdelegate hash_hex(data, algorithm), to: Altcha.V1
  defdelegate hmac_hash(data, algorithm, key), to: Altcha.V1
  defdelegate hmac_hex(data, algorithm, key), to: Altcha.V1
  defdelegate create_challenge(options), to: Altcha.V1
  defdelegate verify_solution(payload, hmac_key), to: Altcha.V1
  defdelegate verify_solution(payload, hmac_key, check_expires), to: Altcha.V1
  defdelegate verify_fields_hash(form_data, fields, fields_hash, algorithm), to: Altcha.V1
  defdelegate verify_server_signature(payload, hmac_key), to: Altcha.V1
  defdelegate extract_params(payload), to: Altcha.V1
  defdelegate solve_challenge(challenge, salt), to: Altcha.V1
  defdelegate solve_challenge(challenge, salt, algorithm), to: Altcha.V1
  defdelegate solve_challenge(challenge, salt, algorithm, max), to: Altcha.V1
  defdelegate solve_challenge(challenge, salt, algorithm, max, start), to: Altcha.V1
end
