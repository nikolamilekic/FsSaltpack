module SaltShaker.MainViewEventProcessor

open FSharpPlus

let processEvent state = function
    | KeyViewEvent e ->
        let fromBase = { state with KeyViewState = KeyViewEventProcessor.processEvent state.KeyViewState e }
        match e with
        | KeyUnloaded -> zero
        | KeyEntered (sk, pk) ->
            { fromBase with
                EncryptViewState = { zero with Keypair = Some (sk, pk) }
                DecryptViewState = { zero with Keypair = Some (sk, pk) } }
        | _ -> fromBase
    | DecryptViewEvent e ->
        { state with DecryptViewState = EncryptDecryptEventProcessor.processEvent state.DecryptViewState e }
    | EncryptViewEvent e ->
        { state with EncryptViewState = EncryptDecryptEventProcessor.processEvent state.EncryptViewState e }
