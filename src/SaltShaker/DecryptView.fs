module SaltShaker.DecryptView

open System
open System.Threading
open FSharp.Control.Reactive
open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Interactivity

let make (state : EncryptDecryptState) dispatch = Grid.create [
    Grid.rowDefinitions "Auto * Auto *"
    Panel.classes [ "main-panel" ]
    Panel.children [
        TextBlock.create [ Grid.row 0; TextBlock.text "Cipher Text:" ]
        TextBox.create [
            Grid.row 1
            yield! EncryptDecryptCommon.bigTextBoxProperties
            TextBox.text state.CipherText
            TextBox.errors (if String.IsNullOrEmpty state.CipherTextError then  [] else [ state.CipherTextError ])
            TextBox.init (fun (tb : TextBox) ->
                let handler (args : RoutedEventArgs) =
                    dispatch (UpdateCipherText (args.Source :?> TextBox).Text)
                    dispatch Decrypt

                tb.TextChanged
                |> Observable.throttle (TimeSpan.FromMilliseconds 300.)
                |> Observable.observeOnContext SynchronizationContext.Current
                |> Observable.subscribe handler
                |> ignore

                tb.LostFocus.Add handler)
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


