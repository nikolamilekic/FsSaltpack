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
    | LoadKeys
type KeyViewEvent =
    | SecretKeyUpdated of string
    | KeyLoaded of PublicKeyEncryption.SecretKey * PublicKeyEncryption.PublicKey
    | KeyUnloaded
    | SecretKeyErrorOccurred of string
