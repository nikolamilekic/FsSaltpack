namespace SaltShaker

open FsSodium

type DecryptViewState =
    {
        PlainText : string
        CipherText : string
        Keypair : (PublicKeyEncryption.SecretKey * PublicKeyEncryption.PublicKey) option
        CipherTextError : string
        Sender : PublicKeyEncryption.PublicKey option
    }
    static member Zero = {
        PlainText = ""
        CipherText = ""
        Keypair = None
        CipherTextError = ""
        Sender = None
    }

type DecryptViewCommand =
    | Decrypt of string
    | UpdateCipherText of string
type DecryptViewEvent =
    | CipherTextUpdated of string
    | TextDecrypted of PublicKeyEncryption.PublicKey option * string
    | TextDecryptionFailed of string
