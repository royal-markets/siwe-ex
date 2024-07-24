defmodule Siwe.AsyncRuntimeOptions do
  @moduledoc false

  defstruct worker_threads: nil,
            enable_time: true,
            enable_io: true
end
