if Code.ensure_loaded?(Plug.Conn) do
  defmodule Altcha.Plug.Challenge do
    @moduledoc """
    A `Plug` that serves a freshly signed ALTCHA v2 proof-of-work challenge as JSON.

    Mount it wherever you want the challenge endpoint to live and point the ALTCHA
    widget's `challenge` at the same path.

    This plug only handles `GET` requests; any other method passes through
    untouched, so it is safe to place in a shared pipeline.

    ## Configuration

    Options given where the plug is mounted take precedence over application config:

        config :altcha, Altcha.Plug.Challenge,
          hmac_signature_secret: {System, :fetch_env!, ["ALTCHA_HMAC_SECRET"]}

    ### Options

      * `:hmac_signature_secret` (**required**) - secret used to sign the challenge
        parameters. Accepts a string, a zero-arity function, or an
        `{module, function, args}` tuple. Functions and MFA tuples are resolved on
        every request, so reading the value from the environment is safe.
      * `:hmac_key_signature_secret` - secret for signing the pre-computed derived
        key. Only meaningful together with `:counter` (deterministic mode). Same
        value shapes as `:hmac_signature_secret`.
      * `:algorithm` - key derivation algorithm string, default `"PBKDF2/SHA-256"`.
      * `:cost` - proof-of-work cost, default `10_000`.
      * `:expires_in` - challenge lifetime in seconds, default `600`.
      * `:counter` - fixed counter for deterministic challenges (advanced). A
        zero-arity function may be given to randomise it per request.

    ## Usage

    In a Phoenix router:

        scope "/altcha" do
          forward "/challenge", Altcha.Plug.Challenge
        end

    As a plain `Plug` pipeline entry:

        plug Altcha.Plug.Challenge, cost: 50_000

    On the client:

        <altcha-widget challenge="/altcha/challenge"></altcha-widget>

    See the [Phoenix integration guide](phoenix.html) for the full picture.
    """

    @behaviour Plug

    import Plug.Conn

    @default_algorithm "PBKDF2/SHA-256"
    @default_cost 10_000
    @default_expires_in 600

    @impl true
    def init(opts) when is_list(opts) do
      opts = Keyword.merge(Application.get_env(:altcha, __MODULE__, []), opts)

      unless Keyword.has_key?(opts, :hmac_signature_secret) do
        raise ArgumentError,
              "#{inspect(__MODULE__)} requires a :hmac_signature_secret option, set either " <>
                "inline or via `config :altcha, #{inspect(__MODULE__)}, hmac_signature_secret: ...`"
      end

      %{
        hmac_signature_secret: Keyword.fetch!(opts, :hmac_signature_secret),
        hmac_key_signature_secret: Keyword.get(opts, :hmac_key_signature_secret),
        algorithm: Keyword.get(opts, :algorithm, @default_algorithm),
        cost: Keyword.get(opts, :cost, @default_cost),
        expires_in: Keyword.get(opts, :expires_in, @default_expires_in),
        counter: Keyword.get(opts, :counter)
      }
    end

    @impl true
    def call(%Plug.Conn{method: "GET"} = conn, opts) do
      challenge =
        Altcha.V2.create_challenge(%Altcha.V2.CreateChallengeOptions{
          algorithm: opts.algorithm,
          cost: opts.cost,
          counter: resolve(opts.counter),
          expires_at: DateTime.add(DateTime.utc_now(), opts.expires_in, :second),
          hmac_signature_secret: resolve(opts.hmac_signature_secret),
          hmac_key_signature_secret: resolve(opts.hmac_key_signature_secret)
        })

      conn
      |> put_resp_content_type("application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(200, Jason.encode!(challenge))
      |> halt()
    end

    def call(conn, _opts), do: conn

    defp resolve(nil), do: nil
    defp resolve(fun) when is_function(fun, 0), do: fun.()

    defp resolve({mod, fun, args}) when is_atom(mod) and is_atom(fun) and is_list(args),
      do: apply(mod, fun, args)

    defp resolve(value), do: value
  end
end
