module SaltShaker.MainViewEventProcessor

open FSharpPlus

let processEvent state = function
    | KeyViewEvent e ->
        let fromBase = { state with KeyViewState = KeyViewEventProcessor.processEvent state.KeyViewState e }
        match e with
        | KeyUnloaded -> zero
        | KeyLoaded (sk, pk) ->
            { fromBase with
                EncryptViewState = { zero with Keypair = Some (sk, pk) }
                DecryptViewState = { zero with Keypair = Some (sk, pk) } }
        | _ -> fromBase
    | DecryptViewEvent e ->
        { state with DecryptViewState = DecryptViewEventProcessor.processEvent state.DecryptViewState e }
    | EncryptViewEvent e ->
        { state with EncryptViewState = EncryptViewEventProcessor.processEvent state.EncryptViewState e }
