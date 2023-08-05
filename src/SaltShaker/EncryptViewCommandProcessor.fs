module SaltShaker.EncryptViewCommandProcessor

open System.Text
open FsSaltpack
open FSharpPlus
open FsSodium
open Milekic.FsBech32

let processCommand state = function
    | UpdatePlainText x -> [ PlainTextUpdated x ]
    | Encrypt ->
        if state.PlainText = "" then [ TextEncrypted "" ] else
        if state.LastPlainTextInput = state.PlainText then [] else

        match state.Keypair with
        | None -> []
        | Some (sk, pk) ->
            let input = state.PlainText |> Encoding.UTF8.GetBytes
            let recipients =
                (Encryption.RecipientType.Public, pk)::
                (state.Recipients |>> fun x -> Encryption.RecipientType.Anonymous, x)
            let output = Encryption.encrypt (Some (sk, pk)) recipients input |> Result.get
            let armored = Armoring.armor None Armoring.Mode.EncryptedMessage output
            [ TextEncrypted armored ]
    | AddRecipient ->
        let result = monad.strict {
            let! _, publicKeyBytes = Bech32.decode state.AddRecipientInput |> first (fun x -> x.ToString())
            return! PublicKeyEncryption.PublicKey.Import publicKeyBytes |> first (konst "Public key is invalid")
        }
        match result with
        | Ok pk -> [ RecipientAdded pk ]
        | Error e -> [ AddingRecipientFailed e ]
    | UpdateAddRecipientInput x -> [ AddRecipientInputUpdated x ]
    | ClearRecipients -> [ RecipientsCleared ]
