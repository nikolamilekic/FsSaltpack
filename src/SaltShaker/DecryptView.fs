module SaltShaker.DecryptView

open System
open System.Threading
open FSharp.Control.Reactive
open FSharpPlus
open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Interactivity
open Milekic.FsBech32

let make (state : DecryptViewState) dispatch = Grid.create [
    Grid.rowDefinitions "Auto 110 Auto * Auto"
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
                    dispatch (Decrypt (args.Source :?> TextBox).Text)

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

        let senderDescription =
            match state.Sender with
            | None when state.PlainText <> "" -> "Unknown"
            | None -> ""
            | Some sender ->
                let shorthand = KeyHandling.publicKeyToTwoWordId sender
                $"{Bech32.encode KeyViewEventProcessor.publicKeyPrefix sender.Get |> Result.get} ({shorthand})"

        StackPanel.create [
            Grid.row 4
            Panel.children [
                TextBlock.create [ TextBlock.text "Sender:" ]
                TextBox.create [
                    TextBox.text senderDescription
                    TextBox.isReadOnly true
                ]
            ]
        ]
    ]
]


