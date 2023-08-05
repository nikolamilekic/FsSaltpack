module SaltShaker.KeyViewEventProcessor

open FSharpPlus
open Milekic.FsBech32

let secretKeyPrefix = HumanReadablePrefix.Validate "spsk" |> Result.get
let publicKeyPrefix = HumanReadablePrefix.Validate "sppk" |> Result.get

let processEvent state = function
    | SecretKeyUpdated x -> { state with SecretKey = x; SecretKeyError = "" }
    | SecretKeyErrorOccurred x -> { state with SecretKeyError = x }
    | KeyUnloaded -> zero
    | KeyEntered (sk, pk) ->
        { state with
            SecretKey = Bech32.encode secretKeyPrefix sk.Get |> Result.get
            PublicKey = Bech32.encode publicKeyPrefix pk.Get |> Result.get
            CanEnter = false
            CanUnload = true
            CanChangeSecretKey = false }
