# Phoenix integration

This guide wires the [ALTCHA](https://altcha.org) widget into a Phoenix app: load
the widget script, serve proof-of-work challenges with `Altcha.Plug.Challenge`, and
verify the submitted solution on the server.

It uses the v2 API (`Altcha.V2`). For the older widget, the same shape applies with
`Altcha.V1`.

## 1. Install

```elixir
# mix.exs
defp deps do
  [
    {:altcha, "~> 2.0"}
  ]
end
```

`Altcha.Plug.Challenge` needs `:plug`, which Phoenix already brings in. It is an
`optional` dependency of `:altcha`, so nothing is pulled in for non-Phoenix users.

Put the signing secret in the environment and read it in `config/runtime.exs`:

```elixir
# config/runtime.exs
config :altcha, Altcha.Plug.Challenge,
  hmac_signature_secret: System.fetch_env!("ALTCHA_HMAC_SECRET")
```

Generate a secret with `mix phx.gen.secret` (or any 32+ byte random string).

## 2. Load the widget script

Pick **one** of the following. A pinned CDN tag is the simplest and matches ALTCHA's
own documentation.

### Option A - CDN

Add to your root layout, pinning the version. Use the `dist/main` build - it bundles
the styles and the PBKDF2/SHA workers into one file. (`dist/external` splits the CSS
out and drops the workers; only reach for it under a strict CSP.)

```heex
<script
  type="module"
  src="https://cdn.jsdelivr.net/npm/altcha@3.2.2/dist/main/altcha.min.js"
  async
  defer
></script>
```

### Option B - npm

If your app has an `assets/package.json`:

```bash
npm install altcha --prefix assets
```

```javascript
// assets/js/app.js
import "altcha";
```

### Option C - vendored file

Fetch the script once, commit it, and import it locally (this is how Phoenix vendors
`topbar.js`):

```bash
curl -L https://cdn.jsdelivr.net/npm/altcha@3.2.2/dist/main/altcha.min.js \
  -o assets/vendor/altcha.js
```

```javascript
// assets/js/app.js
import "../vendor/altcha.js";
```

## 3. Serve challenges

Mount `Altcha.Plug.Challenge` in your router. It answers `GET` with a freshly signed
challenge as JSON and ignores every other method.

```elixir
# lib/my_app_web/router.ex
scope "/altcha", MyAppWeb do
  forward "/challenge", Altcha.Plug.Challenge
end
```

Options can be passed inline and override the application config, e.g.
`forward "/challenge", Altcha.Plug.Challenge, cost: 50_000`. See
`Altcha.Plug.Challenge` for the full list (`:algorithm`, `:cost`, `:expires_in`, ...).

Point the widget at that path:

```heex
<form phx-submit="submit">
  <altcha-widget challengeurl={~p"/altcha/challenge"}></altcha-widget>
  <input type="hidden" name="altcha" id="altcha-token-input" />
  <button type="submit">Submit</button>
</form>
```

## 4. LiveView hook

The widget emits a `statechange` event. Copy the payload into the hidden input so it
is submitted with the form.

```javascript
// assets/js/app.js
let Hooks = {};

Hooks.Altcha = {
  mounted() {
    const widget = this.el.querySelector("altcha-widget");
    const input = this.el.querySelector("#altcha-token-input");
    if (!widget || !input) return;

    widget.addEventListener("statechange", ({ detail }) => {
      const { state, payload } = detail || {};
      input.value = state === "verified" && payload ? payload : "";
    });
  },
};

let liveSocket = new LiveSocket("/live", Socket, {
  params: { _csrf_token: csrfToken },
  hooks: Hooks,
});
```

Add `phx-hook="Altcha"` to the form's wrapper element.

For a dead view (regular controller form) the widget populates the input on its own;
no hook is needed.

## 5. Verify the solution

On submit, decode the payload and verify it with the **same secret** used to sign the
challenge:

```elixir
def submit(conn, %{"altcha" => token} = params) do
  secret = Application.fetch_env!(:altcha, Altcha.Plug.Challenge)[:hmac_signature_secret]

  result =
    token
    |> Altcha.V2.decode_payload()
    |> case do
      %Altcha.V2.Payload{} = payload ->
        Altcha.V2.verify_solution(%Altcha.V2.VerifySolutionOptions{
          challenge: payload.challenge,
          solution: payload.solution,
          hmac_signature_secret: secret
        })

      nil ->
        %Altcha.V2.VerifySolutionResult{verified: false}
    end

  if result.verified do
    # ... proceed
  else
    # ... reject: result.expired / result.invalid_signature / result.invalid_solution
  end
end
```

In LiveView, do the same inside `handle_event/3`.

### Optional: bind the challenge to form fields

If you render `<altcha-widget verifyurl=...>` with `verifyfields`, the widget submits
a fields hash you can check with
`Altcha.V2.verify_fields_hash/4`.

### Optional: Cloud or Sentinel

When you use the hosted [ALTCHA Sentinel](https://altcha.org/docs/v2/api/) endpoint,
the submitted token is a server-signed payload. Verify it with
`Altcha.V2.verify_server_signature/2`, which also returns the parsed classification /
score data.
