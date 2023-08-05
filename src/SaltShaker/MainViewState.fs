namespace SaltShaker

open FSharpPlus

type MainViewState =
    {
        KeyViewState : KeyViewState
        EncryptViewState : EncryptViewState
        DecryptViewState : DecryptViewState
    }
    static member Zero = {
        KeyViewState = zero
        EncryptViewState = zero
        DecryptViewState = zero
    }
    member this.EncryptionEnabled = this.EncryptViewState.Keypair.IsSome
    member this.DecryptionEnabled = this.DecryptViewState.Keypair.IsSome

type MainViewCommand =
    | KeyViewCommand of KeyViewCommand
    | EncryptViewCommand of EncryptViewCommand
    | DecryptViewCommand of DecryptViewCommand
type MainViewEvent =
    | KeyViewEvent of KeyViewEvent
    | EncryptViewEvent of EncryptViewEvent
    | DecryptViewEvent of DecryptViewEvent
