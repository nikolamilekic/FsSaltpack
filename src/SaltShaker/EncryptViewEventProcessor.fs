module SaltShaker.EncryptViewEventProcessor

let processEvent state = function
    | PlainTextUpdated x -> { state with PlainText = x }
    | TextEncrypted x -> { state with CipherText = x; LastPlainTextInput = state.PlainText }
    | AddingRecipientFailed e -> { state with RecipientInputError = e }
    | RecipientAdded pk ->
        { state with
            Recipients = pk::state.Recipients
            RecipientInputError = ""
            AddRecipientInput = ""
            CipherText = ""
            LastPlainTextInput = "" }
    | RecipientsCleared ->
        { state with
            Recipients = []
            RecipientInputError = ""
            AddRecipientInput = "" }
    | AddRecipientInputUpdated x -> { state with AddRecipientInput = x; RecipientInputError = "" }
