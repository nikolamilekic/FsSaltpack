namespace SaltShaker

open FsSodium

type EncryptViewState =
    {
        PlainText : string
        CipherText : string
        LastPlainTextInput : string
        Keypair : (PublicKeyEncryption.SecretKey * PublicKeyEncryption.PublicKey) option
        Recipients : PublicKeyEncryption.PublicKey list
        AddRecipientInput : string
        RecipientInputError : string
    }
    static member Zero = {
        PlainText = ""
        CipherText = ""
        LastPlainTextInput = ""
        Keypair = None
        Recipients = []
        AddRecipientInput = ""
        RecipientInputError = ""
    }

type EncryptViewCommand =
    | UpdatePlainText of string
    | Encrypt
    | AddRecipient
    | ClearRecipients
    | UpdateAddRecipientInput of string
type EncryptViewEvent =
    | PlainTextUpdated of string
    | TextEncrypted of string
    | RecipientAdded of PublicKeyEncryption.PublicKey
    | AddingRecipientFailed of string
    | RecipientsCleared
    | AddRecipientInputUpdated of string
