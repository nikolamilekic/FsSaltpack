module SaltShaker.EncryptView

open System
open System.Threading
open Avalonia.Interactivity
open FSharp.Core
open FSharp.Control.Reactive
open Avalonia.FuncUI.DSL
open Avalonia.Controls

let make (state : EncryptDecryptState) dispatch = Grid.create [
    Grid.rowDefinitions "Auto * Auto *"
    Panel.classes [ "main-panel" ]
    Panel.children [
        TextBlock.create [ Grid.row 0; TextBlock.text "Plain Text:" ]
        TextBox.create [
            Grid.row 1
            yield! EncryptDecryptCommon.bigTextBoxProperties
            TextBox.text state.PlainText
            TextBox.init (fun (tb : TextBox) ->
                let handler (args : RoutedEventArgs) =
                    dispatch (UpdatePlainText (args.Source :?> TextBox).Text)
                    dispatch Encrypt

                tb.TextChanged
                |> Observable.throttle (TimeSpan.FromMilliseconds 300.)
                |> Observable.observeOnContext SynchronizationContext.Current
                |> Observable.subscribe handler
                |> ignore

                tb.LostFocus.Add handler)
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
