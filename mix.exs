defmodule Altcha.MixProject do
  use Mix.Project

  def project do
    [
      app: :altcha,
      version: "0.1.0",
      elixir: "~> 1.17",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      name: "Altcha",
      source_url: "https://github.com/altcha-org/altcha-lib-ex"
    ]
  end

  defp description() do
    "A lightweight library for creating and verifying ALTCHA challenges."
  end

  defp package do
    [
      name: "altcha",
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/altcha-org/altcha-lib-ex"}
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    []
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:jason, "~> 1.4"},
      {:ex_doc, "~> 0.14", only: :dev, runtime: false}
    ]
  end
end
