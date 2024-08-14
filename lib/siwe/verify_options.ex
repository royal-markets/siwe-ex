defmodule Siwe.VerifyOptions do
  @moduledoc false

  @type t :: %__MODULE__{}

  defstruct domain: nil,
            nonce: nil,
            timestamp: nil,
            rpc_url: nil
end
