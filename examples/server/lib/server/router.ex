defmodule Server.Router do
  use Plug.Router

  alias Altcha.V2
  alias Altcha.V2.{CreateChallengeOptions, VerifySolutionOptions}

  # HMAC secrets used to sign and verify challenges.
  # In production, load these from environment variables or a secrets manager.
  @hmac_secret System.get_env("ALTCHA_HMAC_SECRET", "change-me-in-production")
  @hmac_key_secret System.get_env("ALTCHA_HMAC_KEY_SECRET", "change-me-in-production-2")

  # Challenge expires after 10 minutes.
  @challenge_ttl_seconds 600

  plug :cors
  plug Plug.Parsers, parsers: [:urlencoded, :multipart], pass: ["*/*"]
  plug :match
  plug :dispatch

  # ---------------------------------------------------------------------------
  # Routes
  # ---------------------------------------------------------------------------

  get "/challenge" do
    counter = Enum.random(5_000..10_000)

    challenge =
      V2.create_challenge(%CreateChallengeOptions{
        algorithm: "PBKDF2/SHA-256",
        cost: 5_000,
        counter: counter,
        expires_at: DateTime.to_unix(DateTime.utc_now(), :second) + @challenge_ttl_seconds,
        hmac_signature_secret: @hmac_secret,
        hmac_key_signature_secret: @hmac_key_secret
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(challenge))
  end

  post "/submit" do
    altcha_payload = conn.body_params["altcha"]

    cond do
      is_nil(altcha_payload) or altcha_payload == "" ->
        json(conn, 400, %{success: false, error: "Missing altcha payload."})

      true ->
        case decode_altcha(altcha_payload) do
          :error ->
            json(conn, 400, %{success: false, error: "Malformed altcha payload."})

          {:client, %V2.Payload{challenge: challenge, solution: solution}} ->
            result =
              V2.verify_solution(%VerifySolutionOptions{
                challenge: challenge,
                solution: solution,
                hmac_signature_secret: @hmac_secret,
                hmac_key_signature_secret: @hmac_key_secret
              })

            status = if result.verified, do: 200, else: 400

            json(conn, status, %{
              success: result.verified,
              altcha: %{
                verified: result.verified,
                expired: result.expired,
                invalid_signature: result.invalid_signature,
                invalid_solution: result.invalid_solution,
                time: result.time
              }
            })

          {:server_signature, raw} ->
            {result, verification_data} = V2.verify_server_signature(raw, @hmac_secret)

            status = if result.verified, do: 200, else: 400

            json(conn, status, %{
              success: result.verified,
              altcha: %{
                verified: result.verified,
                expired: result.expired,
                invalid_signature: result.invalid_signature,
                invalid_solution: result.invalid_solution,
                time: result.time,
                verification_data: verification_data
              }
            })
        end
    end
  end

  match _ do
    send_resp(conn, 404, "Not found")
  end

  # ---------------------------------------------------------------------------
  # CORS
  # ---------------------------------------------------------------------------

  defp cors(conn, _opts) do
    conn =
      conn
      |> put_resp_header("access-control-allow-origin", "*")
      |> put_resp_header("access-control-allow-methods", "GET, POST, OPTIONS")
      |> put_resp_header("access-control-allow-headers", "content-type")

    if conn.method == "OPTIONS" do
      conn |> send_resp(204, "") |> halt()
    else
      conn
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Decodes a Base64 altcha payload and detects its type.
  # Returns {:client, Payload}, {:server_signature, raw_binary}, or :error.
  defp decode_altcha(encoded) do
    with {:ok, raw} <- Base.decode64(encoded),
         {:ok, map} <- Jason.decode(raw) do
      if Map.has_key?(map, "verificationData") do
        {:server_signature, map}
      else
        case V2.decode_payload(encoded) do
          nil -> :error
          payload -> {:client, payload}
        end
      end
    else
      _ -> :error
    end
  end

  defp json(conn, status, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
