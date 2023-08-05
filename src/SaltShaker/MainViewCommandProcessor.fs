module SaltShaker.MainViewCommandProcessor

open FSharpPlus

let processCommand state = function
    | EncryptViewCommand c ->
        let fromBase = EncryptViewCommandProcessor.processCommand state.EncryptViewState c
        fromBase |>> EncryptViewEvent
    | DecryptViewCommand c ->
        let fromBase = DecryptViewCommandProcessor.processCommand state.DecryptViewState c
        fromBase |>> DecryptViewEvent
    | KeyViewCommand c ->
        let fromBase = KeyViewCommandProcessor.processCommand state.KeyViewState c
        fromBase |>> KeyViewEvent
