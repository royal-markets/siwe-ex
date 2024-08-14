defmodule Siwe do
  @moduledoc """
  Siwe provides validation and parsing for Sign-In with Ethereum messages and signatures.
  """

  alias Siwe.{AsyncRuntimeOptions, Message, Native, VerifyOptions}

  @doc """
  Parses a Sign In With Ethereum message string into the Message struct, or reports an error
  """
  @spec parse(String.t()) :: {:ok, Message.t()} | {:error, String.t()}
  defdelegate parse(msg), to: Native

  @doc """
  Converts a Message struct to a Sign In With Ethereum message string, or reports an error
  """
  @spec to_str(Message.t()) :: {:ok, String.t()} | {:error, String.t()}
  defdelegate to_str(msg), to: Native

  @doc """
  Given a Message, signature, and verify options, returns true if:
  the current time or timestamp, if provided, is between the messages'
  not_before and expiration_time the Message.address signing the Message
  would produce the signature.

  The domain, if provided, matches Message.domain
  the nonce, if provided, matches Message.nonce
  """
  @spec verify(Message.t(), String.t(), Keyword.t() | []) :: boolean()
  def verify(msg, sig, opts \\ []) do
    :ok = Native.verify(msg, sig, struct(VerifyOptions, opts))

    receive do
      answer -> answer
    end
  end

  @doc """
  Tests that a message and signature pair correspond and that the current
  time is valid (after not_before, and before expiration_time)

  Returns a Message structure based on the passed message

  ## Examples
    iex> Siwe.parse_if_valid(Enum.join(["login.xyz wants you to sign in with your Ethereum account:",
    ...> "0xfA151B5453CE69ABf60f0dbdE71F6C9C5868800E",
    ...> "",
    ...> "Sign-In With Ethereum Example Statement",
    ...> "",
    ...> "URI: https://login.xyz",
    ...> "Version: 1",
    ...> "Chain ID: 1",
    ...> "Nonce: ToTaLLyRanDOM",
    ...> "Issued At: 2021-12-17T00:38:39.834Z",
    ...> ], "\\n"),
    ...> "0x8d1327a1abbdf172875e5be41706c50fc3bede8af363b67aefbb543d6d082fb76a22057d7cb6d668ceba883f7d70ab7f1dc015b76b51d226af9d610fa20360ad1c")
    {:ok, %Siwe.Message{ address: "0xfA151B5453CE69ABf60f0dbdE71F6C9C5868800E", chain_id: 1, domain: "login.xyz", expiration_time: nil, issued_at: "2021-12-17T00:38:39.834Z", nonce: "ToTaLLyRanDOM", not_before: nil, request_id: nil, resources: [], statement: "Sign-In With Ethereum Example Statement", uri: "https://login.xyz", version: "1" }}
  """
  @spec parse_if_valid(String.t(), String.t(), Keyword.t() | []) ::
          {:ok, Message.t()} | {:error, String.t()}
  def parse_if_valid(msg, sig, opts \\ []) do
    :ok = Native.parse_if_valid(msg, sig, struct(VerifyOptions, opts))

    receive do
      answer -> answer
    end
  end

  @doc """
  Generates an alphanumeric nonce for use in SIWE messages.
  """
  @spec generate_nonce() :: String.t()
  defdelegate generate_nonce, to: Native

  def configure_async_runtime! do
    case Application.get_env(:siwe, :async_runtime_options, %AsyncRuntimeOptions{}) do
      %AsyncRuntimeOptions{} = options ->
        options

      other ->
        raise """
        Unexpected async runtime options.

        Expected: %Siwe.AsyncRuntimeOptions{}
        Found: #{inspect(other)}
        """
    end
  end
end
