defmodule Altcha.Plug.ChallengeTest do
  # async: false because some tests touch Application / System env.
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias Altcha.Plug.Challenge
  alias Altcha.V2

  @secret "test-hmac-secret"

  defp get(opts) do
    Challenge.call(conn(:get, "/altcha/challenge"), Challenge.init(opts))
  end

  defp solve(challenge) do
    V2.solve_challenge(%V2.SolveChallengeOptions{challenge: challenge, timeout: 5_000})
  end

  defp verify(challenge, solution, secret) do
    V2.verify_solution(%V2.VerifySolutionOptions{
      challenge: challenge,
      solution: solution,
      hmac_signature_secret: secret
    })
  end

  describe "init/1" do
    test "raises when :hmac_signature_secret is missing" do
      assert_raise ArgumentError, ~r/hmac_signature_secret/, fn -> Challenge.init([]) end
    end

    test "reads options from application config" do
      Application.put_env(:altcha, Challenge, hmac_signature_secret: @secret, cost: 1)
      on_exit(fn -> Application.delete_env(:altcha, Challenge) end)

      opts = Challenge.init([])
      assert opts.hmac_signature_secret == @secret
      assert opts.cost == 1
    end

    test "inline options override application config" do
      Application.put_env(:altcha, Challenge, hmac_signature_secret: @secret, cost: 1)
      on_exit(fn -> Application.delete_env(:altcha, Challenge) end)

      assert Challenge.init(cost: 99).cost == 99
    end
  end

  describe "call/2" do
    test "GET returns a signed challenge that verifies end to end" do
      conn = get(hmac_signature_secret: @secret, cost: 1)

      assert conn.halted
      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
      assert get_resp_header(conn, "cache-control") == ["no-store"]

      challenge = V2.Challenge.from_json(conn.resp_body)
      assert challenge.signature

      solution = solve(challenge)
      assert %V2.Solution{} = solution
      assert verify(challenge, solution, @secret).verified
    end

    test "a challenge from a different secret does not verify" do
      challenge = V2.Challenge.from_json(get(hmac_signature_secret: @secret, cost: 1).resp_body)
      solution = solve(challenge)

      refute verify(challenge, solution, "other-secret").verified
    end

    test "honours :expires_in" do
      now = DateTime.to_unix(DateTime.utc_now(), :second)
      conn = get(hmac_signature_secret: @secret, cost: 1, expires_in: 42)
      challenge = V2.Challenge.from_json(conn.resp_body)

      assert_in_delta challenge.parameters.expires_at, now + 42, 5
    end

    test "resolves an {m, f, a} secret per request" do
      System.put_env("ALTCHA_TEST_SECRET", @secret)
      on_exit(fn -> System.delete_env("ALTCHA_TEST_SECRET") end)

      conn =
        get(hmac_signature_secret: {System, :fetch_env!, ["ALTCHA_TEST_SECRET"]}, cost: 1)

      challenge = V2.Challenge.from_json(conn.resp_body)
      assert verify(challenge, solve(challenge), @secret).verified
    end

    test "resolves a zero-arity function secret" do
      conn = get(hmac_signature_secret: fn -> @secret end, cost: 1)
      challenge = V2.Challenge.from_json(conn.resp_body)

      assert verify(challenge, solve(challenge), @secret).verified
    end

    test "passes non-GET requests through untouched" do
      conn =
        Challenge.call(
          conn(:post, "/altcha/challenge"),
          Challenge.init(hmac_signature_secret: @secret)
        )

      refute conn.halted
      assert conn.status == nil
    end
  end
end
