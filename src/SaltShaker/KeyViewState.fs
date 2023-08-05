namespace SaltShaker

open FsSodium

type KeyViewState =
    {
        PublicKey : string
        SecretKey : string
        SecretKeyError : string
        CanEnter : bool
        CanUnload : bool
        CanChangeSecretKey : bool
    }
    static member Zero = {
        PublicKey = ""
        SecretKey = ""
        SecretKeyError = ""
        CanEnter = true
        CanUnload = false
        CanChangeSecretKey = true
    }

type KeyViewCommand =
    | UpdateSecretKey of string
    | GenerateKey
    | UnloadKeys
    | EnterKeys
type KeyViewEvent =
    | SecretKeyUpdated of string
    | KeyEntered of PublicKeyEncryption.SecretKey * PublicKeyEncryption.PublicKey
    | KeyUnloaded
    | SecretKeyErrorOccurred of string
