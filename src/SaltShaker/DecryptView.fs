namespace SaltShaker

open System
open Avalonia.FuncUI.DSL
open Avalonia.Controls

type DecryptView() =
    let inputTypingDelay = TypingDelay()

    member _.Make (state : EncryptDecryptState) dispatch = Grid.create [
        Grid.rowDefinitions "Auto * Auto *"
        Panel.classes [ "main-panel" ]
        Panel.children [
            TextBlock.create [ Grid.row 0; TextBlock.text "Cipher Text:" ]
            TextBox.create [
                Grid.row 1
                yield! EncryptDecryptCommon.bigTextBoxProperties
                TextBox.text state.CipherText
                TextBox.errors (if String.IsNullOrEmpty state.CipherTextError then  [] else [ state.CipherTextError ])
                TextBox.onTextChanged (fun text ->
                    dispatch (UpdateCipherText text)
                    inputTypingDelay.OnUserStoppedTyping <- (fun () -> dispatch Decrypt)
                    inputTypingDelay.UserIsTyping())
                TextBox.onLostFocus (fun _ ->
                    inputTypingDelay.OnUserStoppedTyping <- ignore
                    dispatch Decrypt)
            ]
            TextBlock.create [ Grid.row 2; TextBlock.text "Plain Text:" ]
            TextBox.create [
                Grid.row 3
                yield! EncryptDecryptCommon.bigTextBoxProperties
                TextBox.text state.PlainText
                TextBox.isReadOnly true
            ]
        ]
    ]


