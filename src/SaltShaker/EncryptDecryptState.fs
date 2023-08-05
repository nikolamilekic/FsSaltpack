namespace SaltShaker

open FsSodium

type EncryptDecryptState =
    {
        PlainText : string
        CipherText : string
        LastPlainTextInput : string
        Keypair : (PublicKeyEncryption.SecretKey * PublicKeyEncryption.PublicKey) option
        CipherTextError : string
    }
    static member Zero = {
        PlainText = ""
        CipherText = ""
        LastPlainTextInput = ""
        Keypair = None
        CipherTextError = ""
    }

type EncryptDecryptCommand =
    | UpdatePlainText of string
    | UpdateCipherText of string
    | Encrypt
    | Decrypt
type EncryptDecryptEvent =
    | PlainTextUpdated of string
    | CipherTextUpdated of string
    | CipherTextErrorUpdated of string
    | LastPlainTextInputUpdated of string
