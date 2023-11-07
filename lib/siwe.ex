defmodule Siwe do
  @moduledoc """
  Siwe provides validation and parsing for Sign-In with Ethereum messages and signatures.
  """

  alias Siwe.{Message, Native}

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
  Given a Message struct and a signature, returns true if the Message.address
  signing the Message would produce the signature.
  """
  @spec verify_sig(Message.t(), String.t()) :: boolean()
  defdelegate verify_sig(msg, sig), to: Native

  @doc """
  Given a Message, signature, and optionally, domain, nonce and timestamp, returns true if:
  the current time or timestamp, if provided, is between the messages' not_before and expiration_time
  the Message.address signing the Message would produce the signature.
  the domain, if provided, matches Message.domain
  the nonce, if provided, matches Message.nonce
  """
  @spec verify(
          Message.t(),
          String.t(),
          String.t() | nil,
          String.t() | nil,
          String.t() | nil
        ) :: boolean()
  defdelegate verify(msg, sig, domain_binding, match_nonce, timestamp), to: Native

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
  @spec parse_if_valid(String.t(), String.t()) :: {:ok, Message.t()} | {:error, String.t()}
  defdelegate parse_if_valid(msg, sig), to: Native

  @doc """
  Generates an alphanumeric nonce for use in SIWE messages.
  """
  @spec generate_nonce() :: String.t()
  defdelegate generate_nonce, to: Native
end
