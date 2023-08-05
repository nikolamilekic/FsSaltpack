module SaltShaker.EncryptDecryptCommandProcessor

open System.Text
open FsSaltpack
open FSharpPlus

let processCommand state = function
    | UpdatePlainText x -> [ PlainTextUpdated x ]
    | UpdateCipherText x -> [ CipherTextUpdated x ]
    | Encrypt ->
        if state.PlainText = "" then [ CipherTextUpdated "" ] else
        if state.LastPlainTextInput = state.PlainText then [] else

        match state.Keypair with
        | None -> []
        | Some (_, pk) ->
            let input = state.PlainText |> Encoding.UTF8.GetBytes
            let output = Encryption.encrypt None [ Encryption.RecipientType.Public, pk ] input |> Result.get
            let armored = Armoring.armor None Armoring.Mode.EncryptedMessage output
            [ CipherTextUpdated armored; LastPlainTextInputUpdated state.PlainText ]
    | Decrypt ->
        if state.CipherText = "" then [ PlainTextUpdated "" ] else

        match state.Keypair with
        | None -> []
        | Some (sk, pk) ->
            let result = monad.strict {
                let! input =
                    try state.CipherText |> Armoring.dearmor |> Seq.toArray |> Ok
                    with _ -> Error "Cipher text is not properly encoded"
                return! Encryption.decrypt (sk, pk) input |> first (fun x -> x.ToString())
            }
            match result with
            | Error x -> [ CipherTextErrorUpdated x; PlainTextUpdated "" ]
            | Ok (_, plainTextBytes) ->
                let plainText = plainTextBytes |> Encoding.UTF8.GetString
                [ PlainTextUpdated plainText; CipherTextErrorUpdated "" ]
