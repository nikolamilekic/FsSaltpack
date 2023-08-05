module SaltShaker.EncryptDecryptEventProcessor

let processEvent state = function
    | PlainTextUpdated x -> { state with PlainText = x }
    | CipherTextUpdated x -> { state with CipherText = x }
    | CipherTextErrorUpdated x -> { state with CipherTextError = x}
    | LastPlainTextInputUpdated x -> { state with LastPlainTextInput = x }
