module SaltShaker.DecryptViewCommandProcessor

open System.Text
open FsSaltpack
open FSharpPlus

let processCommand state = function
    | UpdateCipherText x -> [ CipherTextUpdated x ]
    | Decrypt input ->
        if input = "" then [ TextDecrypted (None, "") ] else

        match state.Keypair with
        | None -> []
        | Some (sk, pk) ->
            let result = monad.strict {
                let! input =
                    try input |> Armoring.dearmor |> Seq.toArray |> Ok
                    with _ -> Error "Cipher text is not properly encoded"
                return! Encryption.decrypt (sk, pk) input |> first (fun x -> x.ToString())
            }
            match result with
            | Error x -> [ TextDecryptionFailed x ]
            | Ok (sender, plainTextBytes) -> [ TextDecrypted (sender, Encoding.UTF8.GetString plainTextBytes) ]
