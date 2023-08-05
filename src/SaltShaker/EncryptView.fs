namespace SaltShaker

open Avalonia.FuncUI.DSL
open Avalonia.Controls

type EncryptView() =
    let inputTypingDelay = TypingDelay()

    member _.Make (state : EncryptDecryptState) dispatch = Grid.create [
        Grid.rowDefinitions "Auto * Auto *"
        Panel.classes [ "main-panel" ]
        Panel.children [
            TextBlock.create [ Grid.row 0; TextBlock.text "Plain Text:" ]
            TextBox.create [
                Grid.row 1
                yield! EncryptDecryptCommon.bigTextBoxProperties
                TextBox.text state.PlainText
                TextBox.onTextChanged (fun text ->
                    dispatch (UpdatePlainText text)
                    inputTypingDelay.OnUserStoppedTyping <- (fun () -> dispatch Encrypt)
                    inputTypingDelay.UserIsTyping())
                TextBox.onLostFocus (fun _ ->
                    inputTypingDelay.OnUserStoppedTyping <- ignore
                    dispatch Encrypt)
            ]
            TextBlock.create [ Grid.row 2; TextBlock.text "Cipher Text:" ]
            TextBox.create [
                Grid.row 3
                yield! EncryptDecryptCommon.bigTextBoxProperties
                TextBox.text state.CipherText
                TextBox.isReadOnly true
            ]
        ]
    ]
