module SaltShaker.KeyViewCommandProcessor

open FsSodium
open FSharpPlus
open Milekic.FsBech32

let processCommand state = function
    | UnloadKeys -> [ KeyUnloaded ]
    | GenerateKey ->
        let keypair = PublicKeyEncryption.SecretKey.Generate() |> Result.get
        [ KeyEntered keypair ]
    | UpdateSecretKey x -> [ SecretKeyUpdated x ]
    | EnterKeys ->
        let result = monad.strict {
            let! _, secretKeyBytes = Bech32.decode state.SecretKey |> first (fun x -> x.ToString())
            let! sk = PublicKeyEncryption.SecretKey.Import secretKeyBytes |> first (konst "Secret key is not valid")
            let! pk = PublicKeyEncryption.PublicKey.FromSecretKey sk |> first (konst "Could not compute public key from secret key")
            return sk, pk
        }
        match result with
        | Ok kp -> [ KeyEntered kp ]
        | Error e -> [ SecretKeyErrorOccurred e ]
