namespace SaltShaker

open FSharpPlus

type MainViewState =
    {
        KeyViewState : KeyViewState
        EncryptViewState : EncryptDecryptState
        DecryptViewState : EncryptDecryptState
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
    | EncryptViewCommand of EncryptDecryptCommand
    | DecryptViewCommand of EncryptDecryptCommand
type MainViewEvent =
    | KeyViewEvent of KeyViewEvent
    | EncryptViewEvent of EncryptDecryptEvent
    | DecryptViewEvent of EncryptDecryptEvent
