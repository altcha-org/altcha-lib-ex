defmodule Server.Application do
  use Application

  @port 3000

  @impl true
  def start(_type, _args) do
    children = [
      {Bandit, plug: Server.Router, port: @port}
    ]

    opts = [strategy: :one_for_one, name: Server.Supervisor]

    IO.puts("Server running at http://localhost:#{@port}")

    Supervisor.start_link(children, opts)
  end
end
