module SaltShaker.DecryptViewEventProcessor

let processEvent (state : DecryptViewState) = function
    | CipherTextUpdated x ->
        { state with CipherText = x; CipherTextError = ""; PlainText = ""; Sender = None }
    | TextDecrypted (sender, plainText) ->
        { state with PlainText = plainText; CipherTextError = ""; Sender = sender }
    | TextDecryptionFailed e ->
        { state with PlainText = ""; CipherTextError = e; Sender = None }
